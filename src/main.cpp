/*
 * ESP CYBER SENTINEL - MAIN CONTROLLER
 * Central firmware for ESP32. Modes: CORE
 */

// ============================================================================
// SYSTEM INCLUDES
// =============================================================================

#include <Arduino.h>
#include <DNSServer.h>
#include <FS.h>
#include <SPIFFS.h>
#include <WebServer.h>
#include <WiFi.h>
#include <algorithm>
#include <functional>
#include <stdio.h>
#include <vector>
#include <esp_wifi.h>
#include <esp_crc.h> 
#include <esp_wifi_types.h>

// ============================================================================
// CONFIGURATION INCLUDES
// =============================================================================

#include "config.h"
#include "dashboard.h"
#include "feature_extraction.h"
#include "globals.h"
#include "logger.h"
#include "radio_intake.h"
#include "types.h"
#include "threat_analyzer.h"
#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>

// Function declarations
void listSPIFFSFiles();

// ============================================================================
// GLOBAL INSTANCES
// =============================================================================

// Web server instance - Dashboard handles server creation
// Note: Dashboard class manages WebServer instance
// Note: Global variables are declared in globals.h
// Class instances - using consistent instance pattern
RadioIntake radioIntake;
Dashboard dashboard; // Global dashboard instance for loop access


// Task handles
TaskHandle_t radioTaskHandle = NULL;
TaskHandle_t featureTaskHandle = NULL;
TaskHandle_t scoringTaskHandle = NULL;
TaskHandle_t loggingTaskHandle = NULL;
TaskHandle_t heartbeatTaskHandle = NULL;
TaskHandle_t spiffsRetryTaskHandle = NULL;

// Global timing variables
// Note: These are declared in globals.h

// =============================================================================
// FREE RTOS TASKS
// =============================================================================

// Temporary stress-test task
// Assuming your ring buffer handle is declared globally somewhere as:
// extern RingbufHandle_t buf_handle; 

void taskStressTest(void *pvParameters) {
    extern RadioIntake* g_radioIntakeInstance;
    extern volatile bool stressTestActive;
    extern volatile unsigned long stressTestInjectedPackets;
    
    Serial.println("[StressTest] Control task ready. Dashboard toggle: OFF (idle)");
    
    for (;;) {
        if (!stressTestActive) {
            vTaskDelay(pdMS_TO_TICKS(250));
            continue;
        }

#if ENABLE_STRESS_SIM
        if (g_radioIntakeInstance != nullptr) {
            
            for (int i = 0; i < 50; i++) {
                Metadata fakePacket;
                
                fakePacket.ts = millis();
                fakePacket.rssi = random(-85, -40);
                fakePacket.channel = WiFi.channel();
                fakePacket.frame_type = 0;    // 802.11 Management Frame Type
                fakePacket.subtype = 12;      // Deauth Subtype (0x0C)
                fakePacket.length = 26;
                fakePacket.hashed_src_mac = 4294967295U; 
                fakePacket.hashed_dst_mac = 1234567890U;
                fakePacket.ssid[0] = '\0'; 

                if (g_radioIntakeInstance->injectMetadata(fakePacket)) {
                    stressTestInjectedPackets++;
                }

                vTaskDelay(pdMS_TO_TICKS(2)); 
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
#else
        // Stress sim not compiled in — keep the task alive so the API always reports state correctly.
        vTaskDelay(pdMS_TO_TICKS(500));
#endif
    }
}

// Radio intake task with thread safety
void taskRadioIntake(void *pvParameters) {
  Serial.println("Radio intake task started");

  for (;;) {
    // Memory check before operations
    if (ESP.getFreeHeap() < MEMORY_WARNING_THRESHOLD) {
      Serial.println(" Low memory in radio task");
      vTaskDelay(pdMS_TO_TICKS(1000));
      continue;
    }

    radioIntake.processPackets();

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

// Feature extraction task with dynamic scheduling based on system load and threat level
void taskFeatureExtraction(void *pvParameters) {
    FeatureExtraction *featureExtraction = FeatureExtraction::getInstance(&radioIntake);
    Serial.println("[SYSTEM] Intelligence engine initialized.");
    
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(100)); 

        unsigned long lastUpdate = 0;
        if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
            lastUpdate = lastFeatureUpdate;
            xSemaphoreGive(globalStateMutex);
        }

        if (millis() - lastUpdate > FEATURE_WINDOW_MS) {
            // Memory safety check
            if (ESP.getFreeHeap() < MEMORY_WARNING_THRESHOLD) {
                vTaskDelay(pdMS_TO_TICKS(2000));
                continue;
            }

            // Extract features
            FeatureVec tempFeatures = featureExtraction->extractFeatures();

            // Run the live analytics engine
            ThreatReport tempReport = ThreatAnalyzer::analyzeEnvironment(tempFeatures);

            // Thread-safe update of global state AND control parameters
            if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                currentFeatures = tempFeatures;
                currentThreatReport = tempReport; 
                
                currentThreatScore = tempReport.threat_score;
                currentClassification = tempReport.classification;
                
                lastFeatureUpdate = millis(); 

                // Autonomous channel lock logic utilizing the verified struct field
                if (tempReport.threat_score >= 7.0f) {
                    if (currentChannelMode != MODE_MANUAL) {  // UI manual override takes priority
                        currentChannelMode = MODE_THREAT_LOCK;
                        
                        // Map the lock target directly to the target field
                        targetedThreatChannel = tempReport.offending_channel; 
                        lastThreatSeenTime = millis(); // Feed the cooldown watchdog
                    }
                }
                xSemaphoreGive(globalStateMutex);
            }
        }
    }
}

// Logging method that accepts structured data and performance metrics
void taskLogging(void *pvParameters) {
  Serial.println("📝 Logging task started");

  for (;;) {
    // Memory check before logging
    if (ESP.getFreeHeap() < MEMORY_WARNING_THRESHOLD) {
      Serial.println("⚠️  Low memory in logging task");
      vTaskDelay(pdMS_TO_TICKS(1000));
      continue;
    }

    if (millis() - lastLogTime > LOG_INTERVAL_MS) {
      // Thread-safe global state read
      float threatScore;
      String classification;

      if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        threatScore = currentThreatScore;
        classification = currentClassification;
        xSemaphoreGive(globalStateMutex);
      } else {
        Serial.println("⚠️  Could not read global state for logging");
        vTaskDelay(pdMS_TO_TICKS(1000));
        continue;
      }

      Event event;
      event.timestamp = millis();
      event.threat_score = threatScore;
      
      // Extract raw C-string from the Arduino String
      event.classification = classification.c_str(); 

      // Call the static class method directly instead of using a pointer
      Logger::logEvent(event); 

      // Thread-safe counter update
      if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        lastLogTime = millis();
        eventCount++;
        xSemaphoreGive(globalStateMutex);
      }
    }

    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

// Heartbeat method with detailed system status and performance metrics
void taskHeartbeat(void *pvParameters) {
  Serial.println("💓 Heartbeat task started");

  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(HEARTBEAT_INTERVAL_MS));

    Serial.println("==========================================");
    Serial.println("💓 CyberSentinel Heartbeat");
    Serial.println("==========================================");
    Serial.print("🟢 Mode: ");
    Serial.println(getBuildModeStr());
    
    // Log the current radio tuning state
    Serial.print("📻 Radio State: ");
    Serial.print(currentChannelMode == MODE_AUTO_HOP ? "SCANNING" : (currentChannelMode == MODE_THREAT_LOCK ? "LOCKED" : "MANUAL"));
    Serial.print(" | Channel: ");
    Serial.println(currentChannel);
    
    Serial.print("📊 Uptime: ");
    Serial.print(millis() / 1000);
    Serial.println("s");
    Serial.print("🔋 Free Heap: ");
    Serial.print(ESP.getFreeHeap());
    Serial.println(" bytes");
    Serial.print("📈 Heap Usage: ");
    Serial.print((ESP.getHeapSize() - ESP.getFreeHeap()) * 100 /
                 ESP.getHeapSize());
    Serial.println("%");
    Serial.println("⚠️  CPU Temp: ESP32 temperature sensor inaccurate - "
                   "monitoring disabled");
    Serial.print("📡 WiFi Status: ");
    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("Connected");
    } else {
      Serial.println("No Clients");
    }
    Serial.print("🌐 Dashboard: http://");
    if (WiFi.status() == WL_CONNECTED) {
      Serial.println(WiFi.localIP());
    } else {
      Serial.println(FALLBACK_AP_IP);
    }
    Serial.println("✅ All systems operational");
    Serial.println("==========================================");
  }
}

// Web dashboard serving task with persistent link management and watchdog integration
void taskDashboardServe(void *pvParameters) {
  Serial.println("🌐 Dashboard serving task started");
  
  static unsigned long lastWiFiCheck = 0;
  
  for (;;) {
    // Handle incoming web dashboard requests and websocket events
    dashboard.handleRequests();

    // Persistent Software Watchdog Link Loop
    unsigned long now = millis();
    if (now - lastWiFiCheck >= WIFI_CHECK_INTERVAL_MS) {
      lastWiFiCheck = now;
      
      // Check the number of stations connected to our AP
      uint8_t clientsConnected = WiFi.softAPgetStationNum();
      
      // Just a healthy debug log instead of dropping the AP interfaces destructively
      Serial.printf("📊 [DASH] Active UI Clients Connected: %d\n", clientsConnected);
    }

    // Yield 30ms to prevent CPU starvation and allow other FreeRTOS tasks to run
    vTaskDelay(pdMS_TO_TICKS(30));
  }
}

// =============================================================================
// UNIFIED RADIO CONTROLLER (GUERILLA SWEEP - ANCHOR & BLITZ)
// =============================================================================
void taskRadioController(void *pvParameters) {
    Serial.println("📡 [RADIO] Guerilla Sweep (Anchor & Blitz) Restored.");
    
    uint32_t lastFullSweepTime = millis();
    uint32_t lastThreatChannelTime = 0;
    uint32_t lastManualChannelTime = 0;
    const uint32_t THREAT_CHANNEL_DWELL_MS = 200;  // 80% of time: monitor threat channel
    const uint32_t HOME_CHANNEL_DWELL_MS = 50;    // 20% of time: keep dashboard responsive
    const uint32_t MANUAL_CHANNEL_DWELL_MS = 200; // 80% of time (override): monitor manual channel

    for (;;) {
        uint8_t localMode = MODE_AUTO_HOP;
        int localTargetChan = 1;
        int localManualChan = 1;

        if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            localMode = currentChannelMode;
            localTargetChan = targetedThreatChannel;
            localManualChan = currentChannel;
            xSemaphoreGive(globalStateMutex);
        }

        // 1. THREAT LOCK MODE: Time-slice between threat channel and home channel (80/20 split)
        if (localMode == MODE_THREAT_LOCK) {
            esp_wifi_set_promiscuous(true);
            
            // Check if we need to leave threat lock
            if (millis() - lastThreatSeenTime > THREAT_TIME_ELAPSED_MS) {
                Serial.println("🛡️ [RADIO] Threat neutralized. Resuming guerilla sweep.");
                if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
                    currentChannelMode = MODE_AUTO_HOP;
                    xSemaphoreGive(globalStateMutex);
                }
                continue;
            }
            
            // Time-slicing: Alternate between threat channel and home channel (80/20)
            if (millis() - lastThreatChannelTime < THREAT_CHANNEL_DWELL_MS) {
                // 80%: Monitor threat channel
                esp_wifi_set_channel(localTargetChan, WIFI_SECOND_CHAN_NONE);
                digitalWrite(SNIFF_LED, HIGH);
            } else {
                // 20%: Return to home channel for dashboard
                esp_wifi_set_channel(HOME_CHANNEL, WIFI_SECOND_CHAN_NONE);
                digitalWrite(SNIFF_LED, LOW);
                
                // Reset timer to go back to threat channel
                if (millis() - lastThreatChannelTime > (THREAT_CHANNEL_DWELL_MS + HOME_CHANNEL_DWELL_MS)) {
                    lastThreatChannelTime = millis();
                }
            }
            
            vTaskDelay(pdMS_TO_TICKS(10));

        // 2. MANUAL MODE: Time-slice between manual channel and home channel (80/20 split)
        } else if (localMode == MODE_MANUAL) {
            esp_wifi_set_promiscuous(true);
            
            // If manual channel IS home channel, just stay there
            if (localManualChan == HOME_CHANNEL) {
                esp_wifi_set_channel(HOME_CHANNEL, WIFI_SECOND_CHAN_NONE);
                digitalWrite(SNIFF_LED, HIGH);
                vTaskDelay(pdMS_TO_TICKS(100));
                continue;
            }
            
            // Otherwise, time-slice (80% manual, 20% home)
            if (millis() - lastManualChannelTime < MANUAL_CHANNEL_DWELL_MS) {
                // 80%: Monitor user-selected manual channel
                esp_wifi_set_channel(localManualChan, WIFI_SECOND_CHAN_NONE);
                digitalWrite(SNIFF_LED, HIGH);
            } else {
                // 20%: Return to home channel for dashboard
                esp_wifi_set_channel(HOME_CHANNEL, WIFI_SECOND_CHAN_NONE);
                digitalWrite(SNIFF_LED, LOW);
                
                // Reset timer to go back to manual channel
                if (millis() - lastManualChannelTime > (MANUAL_CHANNEL_DWELL_MS + HOME_CHANNEL_DWELL_MS)) {
                    lastManualChannelTime = millis();
                }
            }
            
            vTaskDelay(pdMS_TO_TICKS(10));

        // 3. AUTO HOP MODE: Guerilla Sniffing (Camp on Ch 1, Blitz others)
        } else {
            esp_wifi_set_promiscuous(true); 
            
            // Is it time to run the rapid 360ms background blitz?
            if (millis() - lastFullSweepTime > SWEEP_INTERVAL_MS) {
                digitalWrite(SNIFF_LED, HIGH); // Turn LED on for active scanning
                
                for (uint8_t ch = 1; ch <= 13; ch++) {
                    // Update global state so dashboard can capture the channel pulse
                    if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
                        currentChannel = ch;
                        xSemaphoreGive(globalStateMutex);
                    }
                    
                    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
                    vTaskDelay(pdMS_TO_TICKS(30)); // 30ms rapid dwell per channel
                }
                
                digitalWrite(SNIFF_LED, LOW); // Turn off when returning home
                lastFullSweepTime = millis();
            } 
            // Default Phase: Hold the line on Channel 1 so the Web UI stays fluid
            else {
                esp_wifi_set_channel(HOME_CHANNEL, WIFI_SECOND_CHAN_NONE);
                
                if (xSemaphoreTake(globalStateMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
                    currentChannel = HOME_CHANNEL;
                    xSemaphoreGive(globalStateMutex);
                }
                
                digitalWrite(SNIFF_LED, LOW);
                vTaskDelay(pdMS_TO_TICKS(50)); // Short pause to drop CPU overhead
            }
        }
    }
}

void IRAM_ATTR isrManualOverride() {
    currentChannelMode = MODE_MANUAL;
    // Tell the UI we are in manual mode
}

// SPIFFS initialization retry task
void taskSPIFFSRetry(void *pvParameters) {
  Serial.println("🔄 SPIFFS retry task started");

  int retryCount = 0;

  while (retryCount < MAX_RETRIES && !systemStatus.spiffsInitialized) {
    Serial.println("🔄 Retrying SPIFFS initialization... (Attempt " +
                   String(retryCount + 1) + ")");

    if (SPIFFS.begin(true)) {
      Serial.println("✅ SPIFFS initialized successfully");
      systemStatus.spiffsInitialized = true;
      listSPIFFSFiles();
      break;
    }

    retryCount++;
    vTaskDelay(pdMS_TO_TICKS(RETRY_DELAY_MS));
  }

  if (!systemStatus.spiffsInitialized) {
    Serial.println("❌ SPIFFS initialization failed after " +
                   String(MAX_RETRIES) + " attempts");
  }

  vTaskDelete(NULL);
}

// Note: Web server handlers are now handled by Dashboard class
// =============================================================================
// SYSTEM INITIALIZATION
// =============================================================================
void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(200);
  pinMode(SNIFF_LED, OUTPUT);

  // Initialize thread-safe global state and mutexes
  initializeGlobals();

  Serial.println("=========================================");
  Serial.println("🛡️  ESP CYBER SENTINEL BOOTING");
  Serial.println("=========================================");
  Serial.println("🟢 Build Mode: " + String(getBuildModeStr()));
  Serial.println("📅 Firmware: " + String(FW_VERSION));
  Serial.println("🔧 Platform: " + String(ESP.getChipModel()) + " @ " +
                 String(ESP.getCpuFreqMHz()) + "MHz");
  Serial.println("📊 Flash: " + String(ESP.getFlashChipSize() / 1024 / 1024) +
                 "MB");
  Serial.println("=========================================");

  // Initialize SPIFFS
  Serial.println("💾 Initializing SPIFFS filesystem...");
  if (!SPIFFS.begin(true)) {
    Serial.println("❌ SPIFFS initialization failed");
    systemStatus.spiffsInitialized = false;

    // Create background retry task
    xTaskCreate(taskSPIFFSRetry, "SPIFFSRetry", 2048, NULL, 1, NULL);
  } else {
    Serial.println("✅ SPIFFS initialized successfully");
    systemStatus.spiffsInitialized = true;
    listSPIFFSFiles();
  }

  // Initialize WiFi with fallback
  Serial.println("📡 WiFi initialization...");

  // Set up WiFi event handler
  WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info) {
    // Handle WiFi events silently to avoid "Unhandled WiFi event" messages
    switch (event) {
    case SYSTEM_EVENT_STA_DISCONNECTED:
      Serial.println("📡 WiFi disconnected");
      break;
    case SYSTEM_EVENT_STA_CONNECTED:
      Serial.println("📡 WiFi connected");
      break;
    case SYSTEM_EVENT_AP_STACONNECTED:
      Serial.println("📡 Client connected to AP");
      break;
    case SYSTEM_EVENT_AP_STADISCONNECTED:
      Serial.println("📡 Client disconnected from AP");
      break;
    default:
      // Silently handle other events
      break;
    }
  });

  // Note: WiFi event handler is registered above using lambda for cleaner code
  Serial.println("📡 WiFi event handler registered");

  // TACTICAL STANDALONE ACCESS POINT
  Serial.println("\n⚡ [WIFI] Deploying CyberSentinel Standalone Access Point...");
  
  // Set mode to strict Access Point
  WiFi.mode(WIFI_AP);
  
  // Force the SoftAP to anchor to Channel 1 (HOME_CHANNEL)
  // Format: softAP(SSID, password, channel, hidden, max_connections)
  // Anchoring to Channel 1 keeps the radio pinned for the Dashboard clients
  bool apSuccess = WiFi.softAP(AP_SSID, AP_PASS, 1, 0, 4);
  
  if (apSuccess) {
    Serial.println("✅ [WIFI] Tactical AP Successfully Initiated!");
    Serial.printf("📡 SSID: %s\n", AP_SSID);
    Serial.printf("🌐 Dashboard URL: http://%s\n", WiFi.softAPIP().toString().c_str());
    systemStatus.wifiConnected = false; // False because we aren't a station on another network
  } else {
    Serial.println("❌ [WIFI] FATAL: Failed to start Access Point interface!");
  }

  // Setup web server using Dashboard class
  Serial.println("🌐 Initializing dashboard web server...");
  dashboard.init();
  Serial.println("✅ Dashboard web server started on port " + String(WEB_PORT));
  systemStatus.webServerStarted = true;

  // Initialize subsystems
  Serial.println("🔧 Initializing subsystems...");

  // Memory check before subsystem initialization
  size_t freeHeapBefore = ESP.getFreeHeap();
  Serial.printf("📊 Free heap before subsystems: %u bytes\n", freeHeapBefore);

  // Radio intake (direct instance)
  if (radioIntake.begin()) {
    Serial.println("✅ Radio intake initialized");
  } else {
    Serial.println("❌ Radio intake initialization failed");
  }

  // Memory check after radio intake
  size_t freeHeapAfter = ESP.getFreeHeap();
  Serial.printf("📊 Free heap after radio intake: %u bytes (delta: %d)\n",
                freeHeapAfter, (int)(freeHeapAfter - freeHeapBefore));

  if (freeHeapAfter < MEMORY_CRITICAL_THRESHOLD) {
    Serial.println(
        "⚠️  CRITICAL: Low memory detected after radio intake initialization");
  }

  // Feature extraction (singleton)
  FeatureExtraction *featureExtraction =
      FeatureExtraction::getInstance(&radioIntake);
  if (featureExtraction && featureExtraction->initialize()) {
    Serial.println("✅ Feature extraction initialized");
  } else {
    Serial.println("❌ Feature extraction initialization failed");
  }

  // Configure enhanced logger
  Logger::setLogLevel(LOG_INFO);
  Logger::enablePerformanceLogging(true);
  Logger::setLogFormat("json");

  Serial.println("🎯 Enhanced systems initialization complete");

  // Create FreeRTOS tasks with safety checks
  Serial.println("🚀 Creating FreeRTOS tasks...");

  // Final memory check before task creation
  size_t freeHeapBeforeTasks = ESP.getFreeHeap();
  Serial.printf("📊 Free heap before task creation: %u bytes\n",
                freeHeapBeforeTasks);

  // Create tasks with error checking
  BaseType_t result;

  // =========================================================================
  // HARDWARE CAPTURE & TIMING (CORE 0 ONLY)
  // =========================================================================
  // High priority (2) to ensure strict timing for the 30ms sweep window
  xTaskCreatePinnedToCore(taskRadioController, "RadioCtrl", 4096, NULL, 2, 
    NULL, 0 // Strictly Core 0
  );

  // =========================================================================
  // DATA PROCESSING, ANALYTICS & UI (CORE 1 ONLY)
  // =========================================================================
  xTaskCreatePinnedToCore(taskRadioIntake, "RadioIntake", 16384, NULL, 1,
                         &radioTaskHandle, 1);

  xTaskCreatePinnedToCore(taskFeatureExtraction, "FeatureExtraction", 12288, NULL,
                         2, &featureTaskHandle, 1);

  xTaskCreatePinnedToCore(taskLogging, "Logging", 12288, NULL, 1, 
                         &loggingTaskHandle, 1);

  xTaskCreatePinnedToCore(taskHeartbeat, "Heartbeat", 8192, NULL, 0,
                         &heartbeatTaskHandle, 1);

  xTaskCreatePinnedToCore(taskDashboardServe, "DashServe", 8192, NULL, 1, 
    NULL, 1  
  );

  xTaskCreatePinnedToCore(taskStressTest, "StressSim", 4096, NULL, 1, 
    NULL, 1 
  );

  // Memory check after task creation
  size_t freeHeapAfterTasks = ESP.getFreeHeap();
  Serial.printf("📊 Free heap after task creation: %u bytes (used: %u)\n",
                freeHeapAfterTasks, freeHeapBeforeTasks - freeHeapAfterTasks);

  if (freeHeapAfterTasks < MEMORY_WARNING_THRESHOLD) {
    Serial.println("⚠️  WARNING: Low memory after task creation");
  }

  // Final memory status
  size_t finalFreeHeap = ESP.getFreeHeap();
  Serial.printf("📊 Final free heap: %u bytes\n", finalFreeHeap);
  if (finalFreeHeap < MEMORY_CRITICAL_THRESHOLD) {
    Serial.println("🚨 CRITICAL: Very low memory after full initialization");
  }

  Serial.println("=========================================");
  Serial.println("🎉 BOOT SEQUENCE COMPLETED SUCCESSFULLY!");
  Serial.println("🟢 CORE mode ready for operation");
  Serial.println("💓 System monitoring active");
  Serial.print("📡 Dashboard: http://");
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println(WiFi.localIP());
  } else {
    Serial.println(FALLBACK_AP_IP);
  }
  Serial.println("=========================================");
}

// =============================================================================
// MAIN LOOP
// =============================================================================
void loop() {
  // FreeRTOS requires the main loop to yield completely.
  // All processing is handled in dedicated tasks.
  vTaskDelay(pdMS_TO_TICKS(1000)); 
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================
// List SPIFFS files
void listSPIFFSFiles() {
  Serial.println("📁 SPIFFS File Listing:");
  Serial.println("==========================================");
  File root = SPIFFS.open("/");
  File file = root.openNextFile();
  bool dashboardFilesOK = true;


  while (file) {
    Serial.print("📄 ");
    Serial.print(file.name());
    Serial.print(" (");
    Serial.print(file.size());
    Serial.println(" bytes)");


    // Check critical dashboard files
    String fileName = String(file.name());
    if (fileName == PATH_DASHBOARD_HTML ||
        fileName == "/dashboard.html") {
      if (file.size() < DASHBOARD_HTML_MIN_SIZE) {
        Serial.println(
            "⚠️  WARNING: dashboard.html appears corrupted (too small)");
        dashboardFilesOK = false;
      }
    } else if (fileName == PATH_DASHBOARD_CSS ||
               fileName == "/dashboard.css") {
      if (file.size() < DASHBOARD_CSS_MIN_SIZE) {
        Serial.println(
            "⚠️  WARNING: dashboard.css appears corrupted (too small)");
        dashboardFilesOK = false;
      }
    } else if (fileName == PATH_DASHBOARD_JS ||
               fileName == "/dashboard.js") {
      if (file.size() < DASHBOARD_JS_MIN_SIZE) {
        Serial.println(
            "⚠️  WARNING: dashboard.js appears corrupted (too small)");
        dashboardFilesOK = false;
      }
    }


    file = root.openNextFile();
  }


  // Verify critical files exist
  if (!SPIFFS.exists(PATH_DASHBOARD_HTML) &&
      !SPIFFS.exists("/dashboard.html")) {
    Serial.println("❌ ERROR: dashboard.html not found!");
    dashboardFilesOK = false;
  }
  if (!SPIFFS.exists(PATH_DASHBOARD_CSS) &&
      !SPIFFS.exists("/dashboard.css")) {
    Serial.println("❌ ERROR: dashboard.css not found!");
    dashboardFilesOK = false;
  }
  if (!SPIFFS.exists(PATH_DASHBOARD_JS) &&
      !SPIFFS.exists("/dashboard.js")) {
    Serial.println("❌ ERROR: dashboard.js not found!");
    dashboardFilesOK = false;
  }


  if (dashboardFilesOK) {
    Serial.println("✅ All dashboard files verified");
  } else {
    Serial.println(
        "❌ Dashboard file integrity check failed - may cause CSS/JS errors");
  }


  Serial.println("==========================================");
}