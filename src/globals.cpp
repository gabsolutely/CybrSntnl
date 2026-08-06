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

    RecParameter param;
    float from_v, to_v;
    bool  push = false;
    char  reason[96] = {0};

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

            if (p == 0) {
                param = REC_PARAM_DEAUTH;
                from_v = curDeauth;
                to_v   = curDeauth * 2.0f;
                snprintf(reason, sizeof(reason), "%lu false WARNINGs at baseline — raise DEAUTH to reduce noise", cnt);
            } else if (p == 1) {
                param = REC_PARAM_ASSOC;
                from_v = curAssoc;
                to_v   = curAssoc * 1.5f;
                snprintf(reason, sizeof(reason), "%lu false WARNINGs at baseline — raise ASSOC to reduce noise", cnt);
            } else {
                param = REC_PARAM_RSSI_VAR;
                from_v = curRssiVar;
                to_v   = curRssiVar * 1.5f;
                snprintf(reason, sizeof(reason), "%lu false WARNINGs at baseline — raise RSSI_VAR to reduce noise", cnt);
            }
            push = true;
            break;
        }
    }

    if (push) {
        RecEntry e;
        e.timestamp = now;
        e.severity  = REC_SUGGEST;
        e.parameter = param;
        e.from_value = from_v;
        e.to_value   = to_v;
        strncpy(e.reason, reason, sizeof(e.reason) - 1);
        recPush(e);
    }
}

// =============================================================================
// RECOMMENDATION SOURCE B — STRESS POST-CALIBRATION (after stress test ends)
// If user ran stress >= 30s but threat never reached WARNING, recommend
// LOWERING the threshold so it actually catches the test signal.
// =============================================================================
static bool postCalPending = false;
static unsigned long postCalPeakThreatTime = 0;
static float postCalMaxThreat = 0.0f;
static unsigned long postCalStressDurationMs = 0;

void recCheckStressPostCalibration() {
    // Track threat-peak WHILE stress is running
    if (stressTestActive) {
        float s = 0.0f;
        if (globalStateMutex != NULL && xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) == pdTRUE) {
            s = currentThreatReport.threat_score;
            xSemaphoreGive(globalStateMutex);
        }
        if (s > postCalMaxThreat) {
            postCalMaxThreat = s;
            postCalPeakThreatTime = millis();
        }
        postCalPending = true;
        return;
    }

    // Stress just ended — analyze and push recommendations
    if (postCalPending && stressTestStartTime != 0) {
        postCalStressDurationMs = millis() - stressTestStartTime;
        postCalPending = false;

        if (postCalStressDurationMs >= 30000UL && postCalMaxThreat < 2.5f) {
            // Ran a solid 30s+ but nothing tripped — figure out which threshold
            // was too high by looking at which stress params were configured.
            uint32_t cfgRate  = stressCfgRatePktPerSec   ? stressCfgRatePktPerSec   : STRESS_DEFAULT_RATE_PKTS_PER_SEC;
            uint8_t  cfgMask  = (stressCfgFrameTypeMask != 0xFF) ? stressCfgFrameTypeMask : STRESS_DEFAULT_FRAME_TYPE_MASK;

            RecEntry e;
            e.timestamp = millis();
            e.severity  = REC_WARN;

            // Deauth frame types (bit 0 or 1)
            if (cfgMask & 0x3) {
                const float cur = effDeauthThreshold();
                const float approxRate = (cfgRate * 0.6f);
                const float target = approxRate * 0.9f;
                if (target > 0.5f) {
                    e.parameter = REC_PARAM_DEAUTH;
                    e.from_value = cur;
                    e.to_value   = target;
                    snprintf(e.reason, sizeof(e.reason), "%lus stress: peak threat=%.1f — lower DEAUTH so injector is caught", postCalStressDurationMs/1000, postCalMaxThreat);
                    recPush(e);
                }
            }
            // Assoc frame types (bit 2)
            if (cfgMask & 0x4) {
                const float cur = effAssocThreshold();
                const float approxRate = (cfgRate * 0.6f);
                const float target = approxRate * 0.9f;
                if (target > 10.0f) {
                    e.parameter = REC_PARAM_ASSOC;
                    e.from_value = cur;
                    e.to_value   = target;
                    snprintf(e.reason, sizeof(e.reason), "%lus stress: peak threat=%.1f — lower ASSOC so injector is caught", postCalStressDurationMs/1000, postCalMaxThreat);
                    recPush(e);
                }
            }
            // MIXED or spread-channels → RSSI variance
            if ((cfgMask & 0x8) || stressCfgSpreadChannels == 1) {
                const float cur = effRssiVarThreshold();
                e.parameter = REC_PARAM_RSSI_VAR;
                e.from_value = cur;
                e.to_value   = cur * 0.6f;
                snprintf(e.reason, sizeof(e.reason), "%lus stress: peak threat=%.1f — lower RSSI_VAR so variance is caught", postCalStressDurationMs/1000, postCalMaxThreat);
                recPush(e);
            }
        }

        // Reset accumulators for next run
        postCalMaxThreat = 0.0f;
        postCalStressDurationMs = 0;
        stressTestStartTime = 0;
    }
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
    baselineSampleCount = 0;
    memset(baselineFalseWarningCount, 0, sizeof(baselineFalseWarningCount));
    lastBaselineCheck = 0;
    memset(lastRecBaselinePush, 0, sizeof(lastRecBaselinePush));
    postCalPending = false;
    postCalMaxThreat = 0.0f;
    stressTestStartTime = 0;
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