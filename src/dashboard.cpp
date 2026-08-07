#include "dashboard.h"
#include "config.h"
#include "logger.h"
#include "radio_intake.h"
#include "feature_extraction.h"
#include "globals.h"
#include "types.h"
#include <ArduinoJson.h>
#include <FS.h>
#include <SPIFFS.h>
#include <WiFi.h>
#include <esp_wifi.h>

// Externs for shared state (defined in globals.h)
extern ThreatReport currentThreatReport;
extern FeatureVec currentFeatures;
extern RadioIntake radioIntake;

// Static member definition
Dashboard *Dashboard::globalInstance = nullptr;

Dashboard::Dashboard() {
  server = nullptr;      // Instance-specific server
  globalInstance = this; // Set global reference for static handlers
}

Dashboard::~Dashboard() {
  // Clean up server instance to prevent memory leak
  if (server) {
    delete server;
    server = nullptr;
  }
  // Clear global instance reference
  globalInstance = nullptr;
}

// =============================================================================
// INPUT VALIDATION FUNCTIONS
// =============================================================================
// Added comprehensive input validation for all parameters to prevent injection and ensure data integrity
bool Dashboard::validateInput(const String &input, const String &fieldName,
                              int maxLength, bool allowEmpty) {
  if (input.length() == 0 && !allowEmpty) {
    Serial.println("[Dashboard Error] Empty input not allowed for field: " + fieldName);
    return false;
  }

  if (input.length() > maxLength) {
    Serial.println("[Dashboard Error] Input too long for field " + fieldName + ": " +
                               String(input.length()) + " > " +
                               String(maxLength));
    return false;
  }

  // Check for potentially dangerous characters
  if (input.indexOf('<') != -1 || input.indexOf('>') != -1 ||
      input.indexOf('"') != -1 || input.indexOf('\'') != -1 ||
      input.indexOf('&') != -1 || input.indexOf('=') != -1) {
    Serial.println("[Dashboard Error] Invalid characters in field: " + fieldName);
    return false;
  }

  return true;
}

// Added numeric validation for parameters like channel number and thresholds
bool Dashboard::validateNumericInput(const String &input,
                                     const String &fieldName, int minValue,
                                     int maxValue) {
  if (!validateInput(input, fieldName, 10, false)) {
    return false;
  }

  int value = input.toInt();
  if (value < minValue || value > maxValue) {
    Serial.println("[Dashboard Error] Numeric value out of range for " + fieldName +
                               ": " + String(value));
    return false;
  }

  return true;
}

// Added float validation for parameters like threat score thresholds
bool Dashboard::validateFloatInput(const String &input, const String &fieldName,
                                   float minValue, float maxValue) {
  if (!validateInput(input, fieldName, 20, false)) {
    return false;
  }

  float value = input.toFloat();
  if (value < minValue || value > maxValue) {
    Serial.println("[Dashboard Error] Float value out of range for " + fieldName + ": " +
                               String(value));
    return false;
  }

  return true;
}

// Added boolean validation for parameters like AI toggle
bool Dashboard::validateBooleanInput(const String &input,
                                     const String &fieldName) {
  String lowerInput = input;
  lowerInput.toLowerCase();

  if (lowerInput != "true" && lowerInput != "false" && lowerInput != "1" &&
      lowerInput != "0") {
    Serial.println("[Dashboard Error] Invalid boolean value for " + fieldName + ": " + input);
    return false;
  }

  return true;
}

// =============================================================================
// HTTP BASIC AUTHENTICATION
// =============================================================================
// Lightweight gate. Blocks unauthenticated requests to state-changing and
// telemetry endpoints. Read-only /health is intentionally open so monitoring
// tools can ping it without credentials.
bool Dashboard::authorizeRequest(bool requireWrite) {
  (void)requireWrite; // Reserved for future role split (read-only vs admin)

  if (!globalInstance || !globalInstance->server) return false;
  WebServer* srv = globalInstance->server;

#if DASH_AUTH_ENABLED
  if (!srv->authenticate(DASH_AUTH_USER, DASH_AUTH_PASS)) {
    srv->requestAuthentication(BASIC_AUTH, "CyberSentinel Core");
    return false;
  }
#endif

  return true;
}

// Initializes server and endpoints
void Dashboard::init() {
    if (!server)
        server = new WebServer(WEB_PORT);

  // Core handlers
  server->on("/", Dashboard::handleRoot);
  server->on("/dashboard.html", Dashboard::handleRoot);
  server->on("/data", Dashboard::handleData);
  server->on("/events", Dashboard::handleEvents);
  server->on("/csv", Dashboard::handleCSV);

  // Map the routing endpoint for manual overrides
  server->on("/set_channel", Dashboard::handleChannelChangeRequest);

  // Additional handlers for compatibility
  server->on("/health", Dashboard::handleHealth);
  server->on("/system", Dashboard::handleSystem);
  server->on("/stresstest", Dashboard::handleStressTest);
  server->on("/config", Dashboard::handleConfig);

  // Static file handlers
  server->on("/dashboard.css", Dashboard::handleCSS);
  server->on("/dashboard.js", Dashboard::handleJS);
  server->on("/dashboard/chart.min.js", Dashboard::handleChartJS);
  server->on("/favicon.ico", Dashboard::handleFavicon);

  server->onNotFound(Dashboard::handleNotFound);
  server->begin();
}

// Handles incoming HTTP requests
void Dashboard::handleRequests() {
  if (globalInstance && globalInstance->server)
    globalInstance->server->handleClient();
}

// Handles the main dashboard page
void Dashboard::handleRoot() {
  if (!authorizeRequest()) return;
  const char* path = PATH_DASHBOARD_HTML; 

  if (!SPIFFS.exists(path)) {
    if (globalInstance && globalInstance->server)
      globalInstance->server->send(500, "text/plain", "SPIFFS files not available");
    return;
  }

  File file = SPIFFS.open(path, "r");
  if (file) {
    if (globalInstance && globalInstance->server) {
      // Stream directly from the file handler.
      globalInstance->server->streamFile(file, "text/html");
    }
    file.close();
  } else {
    if (globalInstance && globalInstance->server)
      globalInstance->server->send(404, "text/plain", "Dashboard HTML not found");
  }
}

// Handles the /data endpoint, returning JSON with current metrics and threat report
void Dashboard::handleData() {
    if (!authorizeRequest()) return;
    if (!globalInstance || !globalInstance->server) return;

    JsonDocument doc;
    
    uint32_t freeHeap = ESP.getFreeHeap();
    uint32_t heapSize = ESP.getHeapSize();
    float heapUsagePercent = (heapSize > 0) ? ((float)(heapSize - freeHeap) * 100.0f / heapSize) : 0.0f;
    // Check if we're in AP mode or Station mode
    WiFiMode_t wifiMode = WiFi.getMode();
    String wifiStatus = (wifiMode == WIFI_AP || wifiMode == WIFI_AP_STA) ? "AP Mode" : 
                        (WiFi.status() == WL_CONNECTED) ? "Connected" : "Disconnected";
    String wifiIP = (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString() : WiFi.softAPIP().toString();

    // Protected snapshot read of thread-safe global states
    if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) == pdTRUE) {

        // Static rolling average states (retained across network poll ticks)
        static float dynamicAvgThreat = 0.0f;
        static float dynamicAvgEntropy = 0.0f;
        static bool averagesInitialized = false;

        // Initialize historical baseline on the very first successful packet read
        if (!averagesInitialized) {
            dynamicAvgThreat = currentThreatReport.threat_score;
            dynamicAvgEntropy = currentFeatures.mac_entropy;
            averagesInitialized = true;
        } else {
            // 10% weight to current instant value, 90% weight to historical trend
            dynamicAvgThreat = (EMA_WEIGHT * currentThreatReport.threat_score) + ((1.0f - EMA_WEIGHT) * dynamicAvgThreat);
            dynamicAvgEntropy = (EMA_WEIGHT * currentFeatures.mac_entropy) + ((1.0f - EMA_WEIGHT) * dynamicAvgEntropy);
        }

        // Send pure numbers instead of String objects for strict UI validation
        doc["threat_score"] = currentThreatReport.threat_score;
        doc["avg_threat"] = dynamicAvgThreat;
        doc["classification"] = currentThreatReport.classification;
        doc["last_classification"] = currentThreatReport.classification;

        doc["current_channel"] = currentChannel;
        doc["channel_mode"] = (currentChannelMode == MODE_AUTO_HOP) ? "SCANNING" :
                              (currentChannelMode == MODE_THREAT_LOCK) ? "LOCKED" : "MANUAL";

        // Match exact keys from your Javascript validator schema as raw values
        doc["avg_rssi"] = currentFeatures.avg_rssi;
        doc["mac_entropy"] = currentFeatures.mac_entropy;
        doc["avg_entropy"] = dynamicAvgEntropy;
        doc["packet_rate"] = currentFeatures.assoc_rate;

        doc["system_status"] = "GOOD";

        // =========================================================================
        // EVENT SUMMARY — read within mutex for thread safety
        // =========================================================================
        {
            JsonObject summary = doc["event_summary"].to<JsonObject>();
            summary["present"] = latestEventSummary.present;
            summary["timestamp"] = latestEventSummary.timestamp;
            summary["classification"] = latestEventSummary.classification;
            summary["attack_type"] = latestEventSummary.attack_type;
            summary["recommendation"] = latestEventSummary.recommendation;
            summary["source"] = latestEventSummary.source;
            summary["threat_score"] = latestEventSummary.threat_score;
            summary["channel"] = latestEventSummary.channel;
            summary["duration_ms"] = latestEventSummary.duration_ms;
        }

        xSemaphoreGive(globalStateMutex);
    } else {
        doc["system_status"] = "MUTEX_TIMEOUT";
        doc["threat_score"] = 0.0;
        doc["avg_threat"] = 0.0;
        doc["classification"] = "UNKNOWN";
        doc["last_classification"] = "UNKNOWN";
        doc["avg_rssi"] = 0.0;
        doc["mac_entropy"] = 0.00;
        doc["avg_entropy"] = 0.00;
        doc["packet_rate"] = 0;

        // Empty event summary when mutex fails
        JsonObject summary = doc["event_summary"].to<JsonObject>();
        summary["present"] = false;
        summary["timestamp"] = 0;
        summary["classification"] = "";
        summary["attack_type"] = "";
        summary["recommendation"] = "";
        summary["source"] = "";
        summary["threat_score"] = 0.0;
        summary["channel"] = 0;
        summary["duration_ms"] = 0;
    }

    doc["uptime"] = millis() / 1000;
    doc["fw_version"] = FW_VERSION;
    doc["build_mode"] = INTERNAL_BUILD ? "INTERNAL" : "CORE";
    doc["is_internal_build"] = INTERNAL_BUILD;

    // =========================================================================
    // DETECTION THRESHOLDS — runtime globals (raw + effective)
    // =========================================================================
    {
        extern volatile float detectCfgDeauthThreshold;
        extern volatile float detectCfgAssocThreshold;
        extern volatile float detectCfgRssiVarThreshold;
        // Raw stored values (0 = sentinel means "use config.h default")
        doc["detect_cfg_deauth"]     = (float)detectCfgDeauthThreshold;
        doc["detect_cfg_assoc"]      = (float)detectCfgAssocThreshold;
        doc["detect_cfg_rssi_var"]   = (float)detectCfgRssiVarThreshold;
        // Effective values — what threat_analyzer actually compares against
        doc["detect_eff_deauth"]     = effDeauthThreshold();
        doc["detect_eff_assoc"]      = effAssocThreshold();
        doc["detect_eff_rssi_var"]   = effRssiVarThreshold();
    }

    // =========================================================================
    // RECOMMENDATION ENGINE — 4-entry LRU ring (newest first)
    // =========================================================================
    {
        JsonArray recs = doc["recommendations"].to<JsonArray>();
        for (uint8_t i = 0; i < recRingCount && i < REC_RING_SIZE; i++) {
            RecEntry e = recGet(i);
            if (e.timestamp == 0 && i > 0) break; // empty slot beyond head
            JsonObject o = recs.add<JsonObject>();
            o["idx"]       = i;
            o["timestamp"] = e.timestamp;
            o["age_ms"]    = (uint32_t)(millis() - e.timestamp);
            o["severity"]  = recSeverityStr(e.severity);
            o["parameter"] = recParamStr(e.parameter);
            o["from"]      = e.from_value;
            o["to"]        = e.to_value;
            o["reason"]    = String(e.reason);
        }
    }

    // Stress test / synthetic demo injector telemetry + capability flag + runtime config
    {
        extern volatile bool stressTestActive;
        extern volatile unsigned long stressTestInjectedPackets;
        extern volatile uint32_t stressCfgRatePktPerSec;
        extern volatile uint8_t  stressCfgAttackProfile;
        extern volatile uint8_t  stressCfgFrameTypeMask;
        extern volatile int8_t   stressCfgRssiMin;
        extern volatile int8_t   stressCfgRssiMax;
        extern volatile uint8_t  stressCfgMacRandomize;
        extern volatile uint32_t stressCfgBurstOnMs;
        extern volatile uint32_t stressCfgBurstOffMs;
        extern volatile uint32_t stressCfgMicroburstOnMs;
        extern volatile uint32_t stressCfgMicroburstOffMs;
        extern volatile uint8_t  stressCfgSpreadChannels;
        extern volatile uint32_t stressCfgLoopIterationMs;

        doc["stress_active"]   = (bool)stressTestActive;
        doc["stress_injected"] = (uint32_t)stressTestInjectedPackets;
    #if ENABLE_STRESS_SIM
        doc["stress_capable"]  = true;
    #else
        doc["stress_capable"]  = false;
    #endif
        // Runtime config — sentinel values (0 / 0xFF) on first boot mean the
        // task will fall back to the config.h defaults. The dashboard reflects
        // the effective values by reading defaults too when it sees sentinels.
        doc["stress_cfg_rate"]         = (uint32_t)stressCfgRatePktPerSec;
        doc["stress_cfg_profile"]      = (uint8_t)stressCfgAttackProfile;
        doc["stress_cfg_mask"]         = (uint8_t)stressCfgFrameTypeMask;
        doc["stress_cfg_rssi_min"]     = (int)stressCfgRssiMin;
        doc["stress_cfg_rssi_max"]     = (int)stressCfgRssiMax;
        doc["stress_cfg_mac_rand"]     = (uint8_t)stressCfgMacRandomize;
        doc["stress_cfg_burst_on"]     = (uint32_t)stressCfgBurstOnMs;
        doc["stress_cfg_burst_off"]    = (uint32_t)stressCfgBurstOffMs;
        doc["stress_cfg_uburst_on"]    = (uint32_t)stressCfgMicroburstOnMs;
        doc["stress_cfg_uburst_off"]   = (uint32_t)stressCfgMicroburstOffMs;
        doc["stress_cfg_spread_ch"]    = (uint8_t)stressCfgSpreadChannels;
        doc["stress_cfg_loop_ms"]      = (uint32_t)stressCfgLoopIterationMs;
    }
    // Map getPacketCount() to total lifetime packets processed
    doc["packets_processed"] = radioIntake.getPacketCount();
    doc["wifi_status"] = wifiStatus;
    doc["wifi_ip"] = wifiIP;
    doc["free_heap"] = freeHeap;
    doc["isr_queue"] = radioIntake.getBufferSize();
    doc["isr_queue_max"] = MAX_BUFFER_SIZE; // Send the actual dynamic ceiling
    doc["heap_usage_percent"] = heapUsagePercent; 

    String response;
    serializeJson(doc, response);

    globalInstance->server->sendHeader("Connection", "close");
    globalInstance->server->send(200, "application/json", response);
}

// Handles the /events endpoint, returning JSON with current events
void Dashboard::handleEvents() {
    if (!authorizeRequest()) return;
    if (!globalInstance || !globalInstance->server) return;

    JsonDocument doc;
    JsonArray events = doc["events"].to<JsonArray>();
    static int eventId = 1;

    // Isolate cross-core evaluation variables inside a synchronized memory block
    if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) == pdTRUE) {
        float threatScoreSnapshot = currentThreatReport.threat_score;
        String classificationSnapshot = currentThreatReport.classification;
        xSemaphoreGive(globalStateMutex);

        if (threatScoreSnapshot >= HIGH_THREAT_THRESHOLD) {
            JsonObject event1 = events.add<JsonObject>();
            event1["id"] = eventId++;
            event1["classification"] = classificationSnapshot;
            event1["severity"] = "high";
            event1["recommendations"] = JsonArray();
            event1["recommendations"].add("Investigate threat immediately");
            event1["timestamp"] = millis();
        }
    }

    if (radioIntake.getBufferSize() > 0) {
        JsonObject event2 = events.add<JsonObject>();
        event2["id"] = eventId++;
        event2["classification"] = "radio";
        event2["severity"] = "info";
        event2["recommendations"] = JsonArray();
        event2["recommendations"].add("Processing " + String(radioIntake.getBufferSize()) + " packets");
        event2["timestamp"] = millis();
    }

    String response;
    serializeJson(doc, response);

    globalInstance->server->sendHeader("Connection", "close");
    globalInstance->server->send(200, "application/json", response);
}

// Handles the /csv endpoint, returning a CSV report
void Dashboard::handleCSV() {
    if (!authorizeRequest()) return;
    String csv = "timestamp,threat_score,classification,channel\n";
    
    // Protect the read with the mutex!
    if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(CSV_MUTEX_TIMEOUT_MS)) == pdTRUE) {
        csv += String(millis()) + "," + 
               String(currentThreatReport.threat_score) + "," +
               currentThreatReport.classification + "," + 
               String(currentChannel) + "\n";
        xSemaphoreGive(globalStateMutex);
    } else {
        csv += String(millis()) + ",0.0,ERROR,0\n";
    }

    if (globalInstance && globalInstance->server)
        globalInstance->server->send(200, "text/csv", csv);
}

// Handles the /health endpoint, returning JSON with system diagnostics and health status
void Dashboard::handleHealth() {
    JsonDocument doc;
    doc["status"] = "ok";
    doc["uptime"] = millis() / 1000;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["build_mode"] = INTERNAL_BUILD ? "INTERNAL" : "CORE";
    doc["fw_version"] = FW_VERSION;
    {
        extern volatile bool stressTestActive;
        doc["stress_active"] = (bool)stressTestActive;
    #if ENABLE_STRESS_SIM
        doc["stress_capable"] = true;
    #else
        doc["stress_capable"] = false;
    #endif
    }
    doc["timestamp"] = millis();

    // Guard shared state pointers to pull accurate diagnostics across cores
    if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) == pdTRUE) {
        doc["threat_score"] = currentThreatReport.threat_score;
        doc["classification"] = currentThreatReport.classification;
        xSemaphoreGive(globalStateMutex);
    } else {
        doc["threat_score"] = 0.0;
        doc["classification"] = "UNKNOWN";
    }

    String response;
    serializeJson(doc, response);
    if (globalInstance && globalInstance->server)
        globalInstance->server->send(200, "application/json", response);
}

// =============================================================================
// STRESS TEST / DEMO INJECTOR CONTROL ENDPOINT
// =============================================================================
// Runtime toggle for the internal deauth-flood simulator. Exposed so the
// dashboard has a one-click demo button instead of needing a re-flash.
// Handles the /stresstest endpoint. All parameters are OPTIONAL. Pass any
// combination you want; omitted fields keep their previous value.
//
// Query parameters (auth-required for any field that changes state or config):
//   state=1|on|true  / state=0|off|false → toggle the injector
//   rate=<uint>                         → target pkt/sec
//   profile=<0..3>                      → attack profile (see config.h 3B)
//   mask=<uint8>                        → frame-type bitmask (see config.h 3B)
//   rssi_min=<int>                      → dBm
//   rssi_max=<int>                      → dBm
//   mac_rand=<0|1>                      → 1 = randomize src/dst hashes per pkt
//   burst_on=<uint ms>                  → BURSTY on-time
//   burst_off=<uint ms>                 → BURSTY off-time
//   uburst_on=<uint ms>                 → MICROBURST on-time
//   uburst_off=<uint ms>                → MICROBURST off-time
//   spread_ch=<0|1>                     → 1 = vary channel ±2
//   loop_ms=<uint ms>                   → outer loop cadence
//
// (no args) — returns JSON status only (read-only, like /health)
//
// Examples:
//   GET /stresstest?state=on&rate=120&profile=2
//   GET /stresstest?mask=15&rssi_min=-70&rssi_max=-30&mac_rand=1
//   GET /stresstest
void Dashboard::handleStressTest() {
    if (!globalInstance || !globalInstance->server) return;
    WebServer* srv = globalInstance->server;

    extern volatile bool stressTestActive;
    extern volatile unsigned long stressTestInjectedPackets;

    extern volatile uint32_t stressCfgRatePktPerSec;
    extern volatile uint8_t  stressCfgAttackProfile;
    extern volatile uint8_t  stressCfgFrameTypeMask;
    extern volatile int8_t   stressCfgRssiMin;
    extern volatile int8_t   stressCfgRssiMax;
    extern volatile uint8_t  stressCfgMacRandomize;
    extern volatile uint32_t stressCfgBurstOnMs;
    extern volatile uint32_t stressCfgBurstOffMs;
    extern volatile uint32_t stressCfgMicroburstOnMs;
    extern volatile uint32_t stressCfgMicroburstOffMs;
    extern volatile uint8_t  stressCfgSpreadChannels;
    extern volatile uint32_t stressCfgLoopIterationMs;

    JsonDocument doc;

    // Capability flag — CORE builds report capable=false so UI greys out.
#if ENABLE_STRESS_SIM
    const bool capable = true;
#else
    const bool capable = false;
#endif
    doc["stress_capable"] = capable;

    // —— Build the list of fields the caller actually wants to change —— //
    // A write (state change or ANY config update) requires auth. Read-only
    // status is always allowed (same open semantics as /health).
    const bool wantsState    = srv->hasArg("state");
    const bool wantsRate     = srv->hasArg("rate");
    const bool wantsProfile  = srv->hasArg("profile");
    const bool wantsMask     = srv->hasArg("mask");
    const bool wantsRssiMin  = srv->hasArg("rssi_min");
    const bool wantsRssiMax  = srv->hasArg("rssi_max");
    const bool wantsMacRand  = srv->hasArg("mac_rand");
    const bool wantsBurstOn  = srv->hasArg("burst_on");
    const bool wantsBurstOff = srv->hasArg("burst_off");
    const bool wantsUBurstOn = srv->hasArg("uburst_on");
    const bool wantsUBurstOff= srv->hasArg("uburst_off");
    const bool wantsSpreadCh = srv->hasArg("spread_ch");
    const bool wantsLoopMs   = srv->hasArg("loop_ms");

    const bool wantsWrite = wantsState || wantsRate || wantsProfile || wantsMask
                         || wantsRssiMin || wantsRssiMax || wantsMacRand
                         || wantsBurstOn || wantsBurstOff || wantsUBurstOn
                         || wantsUBurstOff || wantsSpreadCh || wantsLoopMs;

    if (wantsWrite) {
        if (!authorizeRequest(true)) return;
        if (!capable) {
            doc["result"]  = "error";
            doc["message"] = "Stress injector not compiled. Flash with 'internal' env (ENABLE_STRESS_SIM=1) or modify config.h.";
            doc["fw_env"]  = "core";
            String out; serializeJson(doc, out);
            srv->send(400, "application/json", out);
            return;
        }
    }

    // Apply each requested field (if any)
    String changedList = "";
    bool stateChangeReported = false;

    if (wantsState) {
        String st = srv->arg("state");
        st.toLowerCase();
        bool want = (st == "1" || st == "on" || st == "true");
        stressTestActive = want;
        if (want) {
            // Timestamp for stress-post-calibration recommendation (>=30s runs)
            stressTestStartTime = millis();
            Serial.println("[StressTest] DASHBOARD TRIGGERED — synthetic injector ON");
        } else {
            Serial.println("[StressTest] Dashboard cleared — synthetic injector OFF");
        }
        changedList += want ? "state=on " : "state=off ";
        stateChangeReported = true;
    }
    if (wantsRate) {
        uint32_t v = srv->arg("rate").toInt();
        if (v < 1) v = 1;
        stressCfgRatePktPerSec = v;
        changedList += "rate=" + String(v) + " ";
    }
    if (wantsProfile) {
        long v = srv->arg("profile").toInt();
        if (v < 0) v = 0;
        if (v > 3) v = 3;
        stressCfgAttackProfile = (uint8_t)v;
        changedList += "profile=" + String(v) + " ";
    }
    if (wantsMask) {
        long v = srv->arg("mask").toInt();
        if (v < 0) v = 0;
        if (v > 15) v = 15;
        stressCfgFrameTypeMask = (uint8_t)v;
        changedList += "mask=" + String(v) + " ";
    }
    if (wantsRssiMin) {
        long v = srv->arg("rssi_min").toInt();
        if (v < -110) v = -110;
        if (v > 0)    v = 0;
        stressCfgRssiMin = (int8_t)v;
        changedList += "rssi_min=" + String(v) + " ";
    }
    if (wantsRssiMax) {
        long v = srv->arg("rssi_max").toInt();
        if (v < -110) v = -110;
        if (v > 0)    v = 0;
        stressCfgRssiMax = (int8_t)v;
        changedList += "rssi_max=" + String(v) + " ";
    }
    if (wantsMacRand) {
        long v = srv->arg("mac_rand").toInt();
        stressCfgMacRandomize = (uint8_t)(v ? 1 : 0);
        changedList += "mac_rand=" + String(stressCfgMacRandomize) + " ";
    }
    if (wantsBurstOn) {
        uint32_t v = srv->arg("burst_on").toInt();
        if (v < 1) v = 1;
        stressCfgBurstOnMs = v;
        changedList += "burst_on=" + String(v) + " ";
    }
    if (wantsBurstOff) {
        uint32_t v = srv->arg("burst_off").toInt();
        if (v < 1) v = 1;
        stressCfgBurstOffMs = v;
        changedList += "burst_off=" + String(v) + " ";
    }
    if (wantsUBurstOn) {
        uint32_t v = srv->arg("uburst_on").toInt();
        if (v < 1) v = 1;
        stressCfgMicroburstOnMs = v;
        changedList += "uburst_on=" + String(v) + " ";
    }
    if (wantsUBurstOff) {
        uint32_t v = srv->arg("uburst_off").toInt();
        if (v < 1) v = 1;
        stressCfgMicroburstOffMs = v;
        changedList += "uburst_off=" + String(v) + " ";
    }
    if (wantsSpreadCh) {
        long v = srv->arg("spread_ch").toInt();
        stressCfgSpreadChannels = (uint8_t)(v ? 1 : 0);
        changedList += "spread_ch=" + String(stressCfgSpreadChannels) + " ";
    }
    if (wantsLoopMs) {
        uint32_t v = srv->arg("loop_ms").toInt();
        if (v < 1) v = 1;
        stressCfgLoopIterationMs = v;
        changedList += "loop_ms=" + String(v) + " ";
    }

    // Echo active state back regardless of whether it was touched
    doc["stress_active"]   = (bool)stressTestActive;
    doc["stress_injected"] = (uint32_t)stressTestInjectedPackets;
    doc["stress_cfg_rate"]       = (uint32_t)stressCfgRatePktPerSec;
    doc["stress_cfg_profile"]    = (uint8_t)stressCfgAttackProfile;
    doc["stress_cfg_mask"]       = (uint8_t)stressCfgFrameTypeMask;
    doc["stress_cfg_rssi_min"]   = (int)stressCfgRssiMin;
    doc["stress_cfg_rssi_max"]   = (int)stressCfgRssiMax;
    doc["stress_cfg_mac_rand"]   = (uint8_t)stressCfgMacRandomize;
    doc["stress_cfg_burst_on"]   = (uint32_t)stressCfgBurstOnMs;
    doc["stress_cfg_burst_off"]  = (uint32_t)stressCfgBurstOffMs;
    doc["stress_cfg_uburst_on"]  = (uint32_t)stressCfgMicroburstOnMs;
    doc["stress_cfg_uburst_off"] = (uint32_t)stressCfgMicroburstOffMs;
    doc["stress_cfg_spread_ch"]  = (uint8_t)stressCfgSpreadChannels;
    doc["stress_cfg_loop_ms"]    = (uint32_t)stressCfgLoopIterationMs;

    if (wantsWrite) {
        doc["result"]  = "ok";
        if (stateChangeReported && stressTestActive) {
            doc["message"] = "Injector running. Applied: " + changedList;
        } else if (stateChangeReported) {
            doc["message"] = "Injector stopped. Applied: " + changedList;
        } else {
            doc["message"] = "Config updated (no state change). Applied: " + changedList;
        }
    } else {
        doc["result"]  = "status";
        doc["message"] = "Read-only. Pass ?state=on, ?rate=N, ?profile=N, ?mask=N, etc. All params optional; auth required for writes.";
    }

    String out; serializeJson(doc, out);
    srv->send(200, "application/json", out);
}

// =============================================================================
// DETECTION CONFIG ENDPOINT — runtime tunable thresholds
// =============================================================================
// GET /config                         → read-only JSON (no auth required)
// GET /config?deauth=2.0&assoc=100    → write (auth required), clamped, saved to NVS
// GET /config?reset=1                 → reset all 3 thresholds to config.h defaults (auth)
//
// Clamping ranges:
//   deauth   → 0.1 pkt/s .. 100 pkt/s
//   assoc    → 5 pkt/s   .. 5000 pkt/s
//   rssi_var → 1 .. 100
void Dashboard::handleConfig() {
    if (!globalInstance || !globalInstance->server) return;
    WebServer* srv = globalInstance->server;

    extern volatile float detectCfgDeauthThreshold;
    extern volatile float detectCfgAssocThreshold;
    extern volatile float detectCfgRssiVarThreshold;

    JsonDocument doc;

    const bool wantsDeauth   = srv->hasArg("deauth");
    const bool wantsAssoc    = srv->hasArg("assoc");
    const bool wantsRssiVar  = srv->hasArg("rssi_var");
    const bool wantsReset    = srv->hasArg("reset");
    const bool wantsWrite = wantsDeauth || wantsAssoc || wantsRssiVar || wantsReset;

    if (!authorizeRequest(true)) return;

    if (wantsWrite && !INTERNAL_BUILD) {
        doc["result"] = "error";
        doc["message"] = "Detection thresholds are read-only in CORE builds.";
        String out; serializeJson(doc, out);
        srv->send(403, "application/json", out);
        return;
    }

    String changedList = "";

    if (wantsReset) {
        nvsResetThresholdsToDefaults();
        changedList = "reset=defaults ";
        Serial.println("[Config] All thresholds reset to config.h defaults");
    }

    if (wantsDeauth) {
        float v = srv->arg("deauth").toFloat();
        if (v < 0.1f)  v = 0.1f;
        if (v > 100.0f) v = 100.0f;
        detectCfgDeauthThreshold = v;
        changedList += "deauth=" + String(v, 2) + " ";
    }
    if (wantsAssoc) {
        float v = srv->arg("assoc").toFloat();
        if (v < 5.0f)    v = 5.0f;
        if (v > 5000.0f) v = 5000.0f;
        detectCfgAssocThreshold = v;
        changedList += "assoc=" + String(v, 2) + " ";
    }
    if (wantsRssiVar) {
        float v = srv->arg("rssi_var").toFloat();
        if (v < 1.0f)   v = 1.0f;
        if (v > 100.0f) v = 100.0f;
        detectCfgRssiVarThreshold = v;
        changedList += "rssi_var=" + String(v, 2) + " ";
    }

    if (wantsWrite) {
        nvsSaveThresholds();
    }

    // Always respond with current effective state
    doc["cfg_deauth"]   = (float)detectCfgDeauthThreshold;
    doc["cfg_assoc"]    = (float)detectCfgAssocThreshold;
    doc["cfg_rssi_var"] = (float)detectCfgRssiVarThreshold;
    doc["eff_deauth"]   = effDeauthThreshold();
    doc["eff_assoc"]    = effAssocThreshold();
    doc["eff_rssi_var"] = effRssiVarThreshold();
    doc["defaults"] = JsonObject();
    doc["defaults"]["deauth"]   = DEAUTH_THRESHOLD;
    doc["defaults"]["assoc"]    = ASSOC_THRESHOLD;
    doc["defaults"]["rssi_var"] = RSSI_VARIANCE_THRESHOLD;

    if (wantsWrite) {
        doc["result"]  = "ok";
        doc["message"] = "Detection thresholds applied: " + changedList + "(persisted to NVS)";
    } else {
        doc["result"]  = "status";
        doc["message"] = "Read-only. Pass ?deauth=N &assoc=N &rssi_var=N to change. Auth required for writes. ?reset=1 reverts to config.h defaults.";
    }

    String out; serializeJson(doc, out);
    srv->send(200, "application/json", out);
}

// Handles the /404 endpoint
void Dashboard::handleNotFound() {
  if (globalInstance && globalInstance->server)
    globalInstance->server->send(404, "text/plain", "404: Not Found");
}

// =============================================================================
// STATIC FILE HANDLERS
// =============================================================================
void Dashboard::handleCSS() {
  if (!authorizeRequest()) return;
  const char* path = PATH_DASHBOARD_CSS;
  File file = SPIFFS.open(path, "r");
  if (file) {
    if (globalInstance && globalInstance->server) {
      globalInstance->server->streamFile(file, "text/css");
    }
    file.close();
  } else {
    if (globalInstance && globalInstance->server)
      globalInstance->server->send(404, "text/plain", "CSS not found");
  }
}

void Dashboard::handleJS() {
  if (!authorizeRequest()) return;
  const char* path = PATH_DASHBOARD_JS;
  File file = SPIFFS.open(path, "r");
  if (file) {
    if (globalInstance && globalInstance->server) {
      globalInstance->server->streamFile(file, "application/javascript");
    }
    file.close();
  } else {
    if (globalInstance && globalInstance->server)
      globalInstance->server->send(404, "text/plain", "JS not found");
  }
}

// Handles the /chart.js endpoint
void Dashboard::handleChartJS() {
  if (!authorizeRequest()) return;
  const char* path = PATH_DASHBOARD_CHARTJS;
  File file = SPIFFS.open(path, "r");
  if (file) {
    if (globalInstance && globalInstance->server) {
      globalInstance->server->streamFile(file, "application/javascript");
    }
    file.close();
  } else {
    if (globalInstance && globalInstance->server)
      globalInstance->server->send(404, "text/plain", "Chart.js not found");
  }
}

// Handles the /favicon.ico endpoint, serving a simple embedded icon
void Dashboard::handleFavicon() {
    // Structural representation of static transparency blocks
    const uint8_t favicon[] = {
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80,
        0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x21, 0xF9, 0x04,
        0x01, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x02, 0x02, 0x04, 0x01, 0x00, 0x3B
    };
    
    if (globalInstance && globalInstance->server) {
        // Stream raw array data using the 4-argument program memory signature variant
        globalInstance->server->send_P(200, "image/gif", (const char*)favicon, sizeof(favicon));
    }
}

// Add the execution handler for setting manual radio states
void Dashboard::handleChannelChangeRequest() {
    if (!authorizeRequest(true)) return; // WRITE-protected (state change)
    if (!globalInstance || !globalInstance->server) return;

    WebServer* srv = globalInstance->server;
    if (srv->hasArg("mode")) {
        String mode = srv->arg("mode");

        if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(CSV_MUTEX_TIMEOUT_MS)) == pdTRUE) {
          if (mode == "auto") {
            currentChannelMode = MODE_AUTO_HOP;
          } 
          else if (mode == "manual" && srv->hasArg("ch")) {
            String channelArg = srv->arg("ch");
            if (validateNumericInput(channelArg, "ch", 1, 13)) {
              currentChannelMode = MODE_MANUAL;
              currentChannel = channelArg.toInt();
              esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
            } else {
              xSemaphoreGive(globalStateMutex);
              srv->send(400, "text/plain", "BAD CHANNEL ARGS");
              return;
            }
          } 
        else { // ✅ Catch invalid or empty configuration operations explicitly
        xSemaphoreGive(globalStateMutex);
        srv->send(400, "text/plain", "INVALID STATE MODE");
        return;
        }
    
    xSemaphoreGive(globalStateMutex);
    srv->send(200, "text/plain", "OK");
    return;
}
    }
    srv->send(400, "text/plain", "BAD REQUEST");
}

// Handles the /system endpoint, returning JSON with system performance and status info
void Dashboard::handleSystem() {
    if (!authorizeRequest()) return;
    if (!globalInstance || !globalInstance->server) return;

    JsonDocument doc;

    // Initialize sub-objects using modern v7 dynamic typing layouts
    JsonObject performance = doc["performance"].to<JsonObject>();
    performance["cpu_freq"] = ESP.getCpuFreqMHz();
    performance["flash_size"] = ESP.getFlashChipSize();
    performance["free_sketch"] = ESP.getFreeSketchSpace();

    doc["free_heap"] = ESP.getFreeHeap();
    doc["heap_usage"] = (ESP.getHeapSize() - ESP.getFreeHeap()) * 100 / ESP.getHeapSize();

    JsonObject wifi = doc["wifi"].to<JsonObject>();
    wifi["connected"] = (WiFi.status() == WL_CONNECTED);
    if (WiFi.status() == WL_CONNECTED) {
        wifi["ip"] = WiFi.localIP().toString();
        wifi["rssi"] = WiFi.RSSI();
    } else {
        wifi["ip"] = WiFi.softAPIP().toString();
        wifi["rssi"] = 0;
    }

    doc["uptime"] = millis() / 1000;
    doc["chip_model"] = ESP.getChipModel();
    doc["chip_revision"] = ESP.getChipRevision();
    doc["network_access"] = "dashboard";

    JsonObject spiffs = doc["spiffs"].to<JsonObject>();
    spiffs["ready"] = true; 
    JsonArray files = spiffs["files"].to<JsonArray>();

    // Dynamically query flash directory bounds for size evaluation metrics
    File root = SPIFFS.open("/");
    File file = root.openNextFile();
    while (file) {
        JsonObject fileObj = files.add<JsonObject>();
        fileObj["name"] = String(file.name());
        fileObj["size"] = file.size();
        file.close();
        file = root.openNextFile();
    }

    JsonArray api_endpoints = doc["api_endpoints"].to<JsonArray>();
    const char* endpoints[] = {"/data", "/events", "/system"};
    for (const char* ep : endpoints) {
        JsonObject epObj = api_endpoints.add<JsonObject>();
        epObj["endpoint"] = ep;
        epObj["status"] = "active";
    }

    String response;
    serializeJson(doc, response);

    globalInstance->server->sendHeader("Connection", "close");
    globalInstance->server->send(200, "application/json", response);
}