#include "globals.h"
#include "config.h"
#include <WiFi.h>

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

// Initialize the global state
void initializeGlobals() {
    // Allocate the hardware mutex before anything tries to use it
    if (globalStateMutex == NULL) {
        globalStateMutex = xSemaphoreCreateMutex();
    }

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