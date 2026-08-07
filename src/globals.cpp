#include "globals.h"
#include "config.h"
#include <WiFi.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <string.h>

// Allocate the actual memory for the externs
ComponentStatus systemStatus = {0};
FeatureVec currentFeatures = {0};
unsigned long lastFeatureUpdate = 0;

// Allocate the actual memory for the externs
float currentThreatScore = 0.0;
String currentClassification = "benign";
ThreatReport currentThreatReport;
EventSummary latestEventSummary = {false, 0, "", "", "", "", 0.0f, 0, 0};

// Allocate the actual memory for the externs
bool mitigationActive = false;
unsigned long lastLogTime = 0;
int eventCount = 0;

// Mutex for protecting global state
SemaphoreHandle_t globalStateMutex = NULL;

// Channel hopping state
ChannelMode currentChannelMode = MODE_AUTO_HOP;
uint8_t currentChannel = 1;
uint8_t targetedThreatChannel = 1;
unsigned long lastThreatSeenTime = 0;

// Stress test / demo injector state (runtime-toggleable)
volatile bool stressTestActive = false;
volatile unsigned long stressTestInjectedPackets = 0;
volatile unsigned long stressTestStartTime = 0;

// Stress test runtime config. Values initialized to 0 so the task falls
// back to config.h STRESS_DEFAULT_* on first run, until the dashboard
// overrides them via /stresstest query params.
volatile uint32_t stressCfgRatePktPerSec   = 0;
volatile uint8_t  stressCfgAttackProfile   = 0xFF; // sentinel: use default
volatile uint8_t  stressCfgFrameTypeMask   = 0xFF;
volatile int8_t   stressCfgRssiMin         = 0;
volatile int8_t   stressCfgRssiMax         = 0;
volatile uint8_t  stressCfgMacRandomize    = 0xFF;
volatile uint32_t stressCfgBurstOnMs       = 0;
volatile uint32_t stressCfgBurstOffMs      = 0;
volatile uint32_t stressCfgMicroburstOnMs  = 0;
volatile uint32_t stressCfgMicroburstOffMs = 0;
volatile uint8_t  stressCfgSpreadChannels  = 0xFF;
volatile uint32_t stressCfgLoopIterationMs = 0;

// Runtime-tunable Detection Thresholds (0 sentinel = use config.h default)
volatile float detectCfgDeauthThreshold = 0.0f;
volatile float detectCfgAssocThreshold  = 0.0f;
volatile float detectCfgRssiVarThreshold = 0.0f;

// Recommendation Ring Buffer (4-entry LRU)
RecEntry recRing[REC_RING_SIZE];
volatile uint8_t recRingHead = 0;
volatile uint8_t recRingCount = 0;

// Baseline drift detector state
float baselineAvgDeauth = 0.0f;
float baselineAvgAssoc  = 0.0f;
float baselineAvgRssiVar = 0.0f;
unsigned long baselineFalseWarningCount[3] = {0, 0, 0};
unsigned long baselineSampleCount = 0;

// =============================================================================
// EFFECTIVE-VALUE HELPERS — fall back to config.h when globals are 0-sentinel
// =============================================================================
float effDeauthThreshold() {
    if (detectCfgDeauthThreshold > 0.0f) return detectCfgDeauthThreshold;
    return DEAUTH_THRESHOLD;
}
float effAssocThreshold() {
    if (detectCfgAssocThreshold > 0.0f) return detectCfgAssocThreshold;
    return ASSOC_THRESHOLD;
}
float effRssiVarThreshold() {
    if (detectCfgRssiVarThreshold > 0.0f) return detectCfgRssiVarThreshold;
    return RSSI_VARIANCE_THRESHOLD;
}

// =============================================================================
// NVS PERSISTENCE for detection thresholds
// =============================================================================
#define NVS_NS "cs_cfg"
#define NVS_KEY_DEAUTH "deauth_th"
#define NVS_KEY_ASSOC  "assoc_th"
#define NVS_KEY_RSSI   "rssi_var_th"

bool nvsLoadThresholds() {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) return false;

    float v = 0.0f;
    size_t sz = sizeof(float);
    if (nvs_get_blob(h, NVS_KEY_DEAUTH, &v, &sz) == ESP_OK && sz == sizeof(float)) {
        detectCfgDeauthThreshold = v;
    }
    sz = sizeof(float);
    if (nvs_get_blob(h, NVS_KEY_ASSOC, &v, &sz) == ESP_OK && sz == sizeof(float)) {
        detectCfgAssocThreshold = v;
    }
    sz = sizeof(float);
    if (nvs_get_blob(h, NVS_KEY_RSSI, &v, &sz) == ESP_OK && sz == sizeof(float)) {
        detectCfgRssiVarThreshold = v;
    }
    nvs_close(h);
    return true;
}

bool nvsSaveThresholds() {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return false;

    float v;
    v = detectCfgDeauthThreshold;
    nvs_set_blob(h, NVS_KEY_DEAUTH, &v, sizeof(float));
    v = detectCfgAssocThreshold;
    nvs_set_blob(h, NVS_KEY_ASSOC,  &v, sizeof(float));
    v = detectCfgRssiVarThreshold;
    nvs_set_blob(h, NVS_KEY_RSSI,   &v, sizeof(float));
    nvs_commit(h);
    nvs_close(h);
    return true;
}

void nvsResetThresholdsToDefaults() {
    detectCfgDeauthThreshold = 0.0f;
    detectCfgAssocThreshold  = 0.0f;
    detectCfgRssiVarThreshold = 0.0f;
    // Wipe from NVS so next boot also gets defaults
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_key(h, NVS_KEY_DEAUTH);
        nvs_erase_key(h, NVS_KEY_ASSOC);
        nvs_erase_key(h, NVS_KEY_RSSI);
        nvs_commit(h);
        nvs_close(h);
    }
}

// =============================================================================
// RECOMMENDATION RING BUFFER HELPERS
// =============================================================================
void recPush(const RecEntry& entry) {
    if (globalStateMutex != NULL) xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS));
    recRingHead = (recRingHead + REC_RING_SIZE - 1) % REC_RING_SIZE;
    memcpy(&recRing[recRingHead], &entry, sizeof(RecEntry));
    if (recRingCount < REC_RING_SIZE) recRingCount++;
    if (globalStateMutex != NULL) xSemaphoreGive(globalStateMutex);
}

void setLatestEventSummary(const char* classification, const char* attackType, const char* recommendation,
                           float threatScore, int channel, unsigned long durationMs, const char* source) {
    if (!classification || !*classification) classification = "NOMINAL";
    if (!attackType || !*attackType) attackType = "Event";
    if (!recommendation || !*recommendation) recommendation = "Review the current airspace conditions.";
    if (!source || !*source) source = "event";

    if (globalStateMutex != NULL) xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS));

    latestEventSummary.present = true;
    latestEventSummary.timestamp = millis();
    latestEventSummary.threat_score = threatScore;
    latestEventSummary.channel = channel;
    latestEventSummary.duration_ms = durationMs;

    strncpy(latestEventSummary.classification, classification, sizeof(latestEventSummary.classification) - 1);
    latestEventSummary.classification[sizeof(latestEventSummary.classification) - 1] = '\0';

    strncpy(latestEventSummary.attack_type, attackType, sizeof(latestEventSummary.attack_type) - 1);
    latestEventSummary.attack_type[sizeof(latestEventSummary.attack_type) - 1] = '\0';

    strncpy(latestEventSummary.recommendation, recommendation, sizeof(latestEventSummary.recommendation) - 1);
    latestEventSummary.recommendation[sizeof(latestEventSummary.recommendation) - 1] = '\0';

    strncpy(latestEventSummary.source, source, sizeof(latestEventSummary.source) - 1);
    latestEventSummary.source[sizeof(latestEventSummary.source) - 1] = '\0';

    if (globalStateMutex != NULL) xSemaphoreGive(globalStateMutex);
}

void clearLatestEventSummary() {
    if (globalStateMutex != NULL) xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS));

    latestEventSummary.present = false;
    latestEventSummary.timestamp = 0;
    latestEventSummary.threat_score = 0.0f;
    latestEventSummary.channel = 0;
    latestEventSummary.duration_ms = 0;
    latestEventSummary.classification[0] = '\0';
    latestEventSummary.attack_type[0] = '\0';
    latestEventSummary.recommendation[0] = '\0';
    latestEventSummary.source[0] = '\0';

    if (globalStateMutex != NULL) xSemaphoreGive(globalStateMutex);
}

RecEntry recGet(uint8_t index) {
    RecEntry e = {0, REC_INFO, REC_PARAM_DEAUTH, 0.0f, 0.0f, {0}};
    if (index >= recRingCount) return e;
    if (globalStateMutex != NULL) xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS));
    uint8_t i = (recRingHead + index) % REC_RING_SIZE;
    memcpy(&e, &recRing[i], sizeof(RecEntry));
    if (globalStateMutex != NULL) xSemaphoreGive(globalStateMutex);
    return e;
}

String recSeverityStr(RecSeverity s) {
    switch (s) {
        case REC_INFO:    return "INFO";
        case REC_SUGGEST: return "SUGGEST";
        case REC_WARN:    return "WARN";
        default:          return "INFO";
    }
}

String recParamStr(RecParameter p) {
    switch (p) {
        case REC_PARAM_DEAUTH:   return "DEAUTH_THRESHOLD";
        case REC_PARAM_ASSOC:    return "ASSOC_THRESHOLD";
        case REC_PARAM_RSSI_VAR: return "RSSI_VARIANCE_THRESHOLD";
        default:                 return "UNKNOWN";
    }
}

// =============================================================================
// RECOMMENDATION SOURCE A — BASELINE DRIFT DETECTOR (every 60s)
// Detects false-WARNING clusters when no stress test is running → recommends
// raising the triggering threshold.
// =============================================================================
static unsigned long lastBaselineCheck = 0;
static unsigned long lastRecBaselinePush[3] = {0, 0, 0}; // per-param debounce

void recCheckBaselineDrift() {
    unsigned long now = millis();
    if (now - lastBaselineCheck < 60000UL) return; // every 60s
    lastBaselineCheck = now;

    FeatureVec f;
    ThreatLevel  tl;
    if (globalStateMutex != NULL && xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) == pdTRUE) {
        f = currentFeatures;
        tl = currentThreatReport.level;
        xSemaphoreGive(globalStateMutex);
    } else {
        return;
    }

    // Update running EMA baseline
    const float BETA = 0.1f;
    baselineAvgDeauth  = BETA * f.disassoc_rate + (1 - BETA) * baselineAvgDeauth;
    baselineAvgAssoc   = BETA * f.assoc_rate    + (1 - BETA) * baselineAvgAssoc;
    baselineAvgRssiVar = BETA * f.rssi_variance + (1 - BETA) * baselineAvgRssiVar;
    baselineSampleCount++;

    if (stressTestActive) return; // no baseline analysis during stress

    // If we got a WARNING/LOW threat but baseline values are well below
    // thresholds, it's a false positive cluster. Count it.
    const bool hitWarning = (tl == THREAT_LOW);
    const float curDeauth  = effDeauthThreshold();
    const float curAssoc   = effAssocThreshold();
    const float curRssiVar = effRssiVarThreshold();

    if (hitWarning && f.disassoc_rate > 0 && f.disassoc_rate < (curDeauth * 0.8f)) {
        baselineFalseWarningCount[0]++;
    }
    if (hitWarning && f.assoc_rate > 0 && f.assoc_rate < (curAssoc * 0.8f)) {
        baselineFalseWarningCount[1]++;
    }
    if (hitWarning && f.rssi_variance > 0 && f.rssi_variance < (curRssiVar * 0.8f)) {
        baselineFalseWarningCount[2]++;
    }

    // Threshold to trigger recommendation: 4+ false WARNINGS in last 10 min
    const unsigned long DEBOUNCE_MS = 10UL * 60UL * 1000UL;

    for (int p = 0; p < 3; p++) {
        if (baselineFalseWarningCount[p] >= 4 && (now - lastRecBaselinePush[p]) > DEBOUNCE_MS) {
            const unsigned long cnt = baselineFalseWarningCount[p]; // capture BEFORE clearing
            lastRecBaselinePush[p] = now;
            baselineFalseWarningCount[p] = 0;

            // Baseline false-positive clusters are tracked, but we no longer emit
            // tuning suggestions here. Mitigation guidance is surfaced from the
            // live attack-profile recommendations when a real threat is detected.
            (void)cnt;
            break;
        }
    }
}

// =============================================================================
// RECOMMENDATION SOURCE B — DISABLED
// Previously handled stress post-calibration, now unified with live threat response.
// Users can calibrate thresholds themselves via the /config endpoint.
// =============================================================================

// =============================================================================
// RECOMMENDATION SOURCE C — LIVE THREAT RESPONSE (every scoring window)
// When a specific attack type is classified, look up the ATTACK_PROFILES
// remediation table and push mitigation/prevention guidance.
// Debounced per attack type so we don't flood the ring every 5s.
// =============================================================================
static unsigned long lastRecAttackPush[ATTACK_PROFILES_COUNT + 1] = {0};

void recCheckLiveThreatResponse(const ThreatReport& report, const FeatureVec& features) {
    if (report.level < THREAT_LOW) return;
    unsigned long now = millis();

    // Resolve attack type by exact matching attack_type against table.
    int attackIdx = -1;
    for (int i = 0; i < (int)ATTACK_PROFILES_COUNT; i++) {
        if (report.attack_type &&
            ATTACK_PROFILES[i].attack_type &&
            strcmp(report.attack_type, ATTACK_PROFILES[i].attack_type) == 0) {
            attackIdx = i;
            break;
        }
    }

    // If no exact type match but threat is >= MEDIUM, fall back to generic
    // suggestion at slot ATTACK_PROFILES_COUNT (debounce slot extra slot).
    const bool genericFallback = (attackIdx < 0 && report.level >= THREAT_MEDIUM);

    // Tiered debounce: CRITICAL=immediate, ACTIVE/MEDIUM=30s, ELEVATED/LOW=60s
    unsigned long DEBOUNCE_MS;
    if (report.level >= THREAT_HIGH) {
        DEBOUNCE_MS = 0; // Immediate for critical threats
    } else if (report.level >= THREAT_MEDIUM) {
        DEBOUNCE_MS = 30UL * 1000UL; // 30s for active/medium
    } else {
        DEBOUNCE_MS = 60UL * 1000UL; // 60s for elevated/low
    }

    int pushIdx = (attackIdx >= 0) ? attackIdx : (int)ATTACK_PROFILES_COUNT;
    if (DEBOUNCE_MS > 0 && (now - lastRecAttackPush[pushIdx]) < DEBOUNCE_MS) {
        return;
    }
    lastRecAttackPush[pushIdx] = now;

    const char* sevLabel = (report.level >= THREAT_HIGH)   ? "CRITICAL"
                         : (report.level >= THREAT_MEDIUM) ? "ACTIVE"
                         :                                    "ELEVATED";

    // ---- 1. Remediation advice (always at least one card) ---------------
    {
        RecEntry e;
        e.timestamp = now;
        e.severity  = (report.level >= THREAT_HIGH)   ? REC_WARN
                    : (report.level >= THREAT_MEDIUM) ? REC_SUGGEST
                    :                                    REC_INFO;
        e.parameter = REC_PARAM_DEAUTH;
        e.from_value = report.threat_score;
        e.to_value   = 0.0f;

        if (attackIdx >= 0) {
            const char* rem = ATTACK_PROFILES[attackIdx].recommendation;
            snprintf(e.reason, sizeof(e.reason), "[%s] %s — score %.1f (%s on ch%d)",
                     sevLabel,
                     (rem && *rem) ? rem : "Mitigate active attack",
                     report.threat_score,
                     report.attack_type ? report.attack_type : "threat",
                     (features.peak_channel > 0) ? features.peak_channel : 1);
        } else if (genericFallback) {
            snprintf(e.reason, sizeof(e.reason),
                     "[%s] Active threat detected (%.1f) — audit APs/STAs on ch%d and enable containment",
                     sevLabel, report.threat_score,
                     (features.peak_channel > 0) ? features.peak_channel : 1);
        } else {
            // LOW threat with unknown attack type - still show something
            snprintf(e.reason, sizeof(e.reason),
                     "[%s] Elevated activity detected (%.1f) — %s on ch%d",
                     sevLabel, report.threat_score,
                     report.attack_type ? report.attack_type : "unknown",
                     (features.peak_channel > 0) ? features.peak_channel : 1);
        }
        recPush(e);

        // Update event summary for live threat display
        const char* recText;
        const char* attackText;

        if (attackIdx >= 0) {
            recText = ATTACK_PROFILES[attackIdx].recommendation;
            attackText = report.attack_type;
        } else if (genericFallback) {
            recText = "Audit APs/STAs on this channel and enable containment";
            attackText = "Active Threat";
        } else {
            // LOW threat with unknown attack type
            recText = "Monitor airspace conditions for escalation";
            attackText = report.attack_type ? report.attack_type : "Elevated Activity";
        }

        const char* source = stressTestActive ? "stress" : "event";
        setLatestEventSummary(sevLabel, attackText, recText, report.threat_score,
                             (features.peak_channel > 0) ? features.peak_channel : 1,
                             0, source);
    }

    // Recommendations are mitigation-focused only; threshold tuning is left to
    // the operator and is intentionally not surfaced here.
    (void)features;
}

// Initialize the global state
void initializeGlobals() {
    // Allocate the hardware mutex before anything tries to use it
    if (globalStateMutex == NULL) {
        globalStateMutex = xSemaphoreCreateMutex();
    }

    // Init NVS (safe to call even if already init'd from core init)
    nvs_flash_init();

    // Load persisted detection thresholds (or keep 0 sentinel → config.h defaults)
    nvsLoadThresholds();

    // Now safe to initialize variables
    currentThreatScore = 0.0;
    currentClassification = "benign";
    lastFeatureUpdate = 0;
    lastLogTime = 0;
    eventCount = 0;
    mitigationActive = false;
    
    systemStatus.wifiConnected = false;
    systemStatus.spiffsInitialized = false;
    systemStatus.webServerStarted = false;
    systemStatus.radioInitialized = false;

    // Reset recommendation ring
    recRingHead = 0;
    recRingCount = 0;
    memset(recRing, 0, sizeof(recRing));
    clearLatestEventSummary();
    baselineSampleCount = 0;
    memset(baselineFalseWarningCount, 0, sizeof(baselineFalseWarningCount));
    lastBaselineCheck = 0;
    memset(lastRecBaselinePush, 0, sizeof(lastRecBaselinePush));
    memset(lastRecAttackPush, 0, sizeof(lastRecAttackPush));
}

// Reset the global state
void resetSystemState() {
    // Prevent crashes if called before initialization
    if (globalStateMutex == NULL) return; 

    if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        currentThreatScore = 0.0;
        currentClassification = "benign";
        mitigationActive = false;
        lastFeatureUpdate = 0;
        eventCount = 0;
        xSemaphoreGive(globalStateMutex);
    }
}

// Generate a JSON string representing the current system status
String getSystemStatusJson() {
    float localScore = 0.0;
    bool localWifi = false, localSpiffs = false, localWeb = false;

    // Guard against NULL pointer exceptions
    if (globalStateMutex != NULL && xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        localScore = currentThreatScore;
        localWifi = systemStatus.wifiConnected;
        localSpiffs = systemStatus.spiffsInitialized;
        localWeb = systemStatus.webServerStarted;
        xSemaphoreGive(globalStateMutex);
    }

    // String manipulation is safe here—completely isolated outside the RTOS lock
    String json = "{\"wifi\":" + String(localWifi ? "true" : "false") + ",";
    json += "\"spiffs\":" + String(localSpiffs ? "true" : "false") + ",";
    json += "\"webserver\":" + String(localWeb ? "true" : "false") + ",";
    json += "\"uptime\":" + String(millis() / 1000) + ",";
    json += "\"free_heap\":" + String(ESP.getFreeHeap()) + ",";
    json += "\"threat_score\":" + String(localScore, 2);
    json += "}";
    return json;
}

// Simple health check function to determine if the system is in a good state
bool checkSystemHealth() {
    bool healthy = false;
    
    if (globalStateMutex != NULL && xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        WiFiMode_t mode = WiFi.getMode();
        bool networkUp = systemStatus.wifiConnected ||
                         mode == WIFI_AP ||
                         mode == WIFI_AP_STA;
        healthy = networkUp && 
                  systemStatus.spiffsInitialized && 
                  systemStatus.webServerStarted;
        xSemaphoreGive(globalStateMutex);
    }
    return healthy && (ESP.getFreeHeap() > 20000); 
}