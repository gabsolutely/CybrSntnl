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
    }

    doc["uptime"] = millis() / 1000;
    doc["fw_version"] = FW_VERSION;
    // Stress test / synthetic demo injector telemetry + capability flag
    {
        extern volatile bool stressTestActive;
        extern volatile unsigned long stressTestInjectedPackets;
        doc["stress_active"] = (bool)stressTestActive;
        doc["stress_injected"] = (uint32_t)stressTestInjectedPackets;
    #if ENABLE_STRESS_SIM
        doc["stress_capable"] = true;
    #else
        doc["stress_capable"] = false;
    #endif
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
    doc["build_mode"] = "CORE";
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
//
// Query parameters (all optional):
//   ?state=1 | on   -> enable stress injector
//   ?state=0 | off  -> disable
//   (no args)       -> read-only JSON status
//
// Examples:
//   GET /stresstest?state=on    // enable (WRITE-protected → needs auth)
//   GET /stresstest?state=off   // disable
//   GET /stresstest             // status (also public like /health — no state change)
void Dashboard::handleStressTest() {
    if (!globalInstance || !globalInstance->server) return;
    WebServer* srv = globalInstance->server;

    extern volatile bool stressTestActive;
    extern volatile unsigned long stressTestInjectedPackets;

    JsonDocument doc;

    // Capability flag — CORE builds report capable=false so UI greys out.
#if ENABLE_STRESS_SIM
    const bool capable = true;
#else
    const bool capable = false;
#endif
    doc["stress_capable"] = capable;
    doc["stress_active"]  = (bool)stressTestActive;

    // —— State change request —— //
    if (srv->hasArg("state")) {
        // Write-gate this. Read-only status above is unauthed.
        if (!authorizeRequest(true)) return;

        String st = srv->arg("state");
        st.toLowerCase();
        bool want = (st == "1" || st == "on" || st == "true");

        if (!capable) {
            doc["result"]  = "error";
            doc["message"] = "Stress injector not compiled. Flash with 'internal' env (ENABLE_STRESS_SIM=1) or modify config.h.";
            doc["fw_env"]  = "core";
            String out; serializeJson(doc, out);
            srv->send(400, "application/json", out);
            return;
        }

        stressTestActive = want;
        if (want) {
            Serial.println("[StressTest] DASHBOARD TRIGGERED — synthetic injector ON");
            doc["result"]  = "enabled";
            doc["message"] = "Simulated deauth flood running. Watch threat score climb.";
        } else {
            Serial.println("[StressTest] Dashboard cleared — synthetic injector OFF");
            doc["result"]  = "disabled";
            doc["message"] = "Injector stopped. Let threat EMA decay back to baseline.";
        }
    } else {
        doc["result"]  = "status";
        doc["message"] = "No state change requested. Pass ?state=on or ?state=off.";
    }

    doc["stress_injected"] = (uint32_t)stressTestInjectedPackets;
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