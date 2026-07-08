/*
 * ===============================================================================
 * ESP CYBER SENTINEL - CONFIGURATION HEADER
 * ===============================================================================
 * VERSION: 1.2.0 (Refactored & De-gunked)
 * ===============================================================================
 */

#ifndef CONFIG_H
#define CONFIG_H

// =============================================================================
// 1. BUILD MODE & TARGET FLAGS
// =============================================================================
// Uncomment your target build profile (or handle via platformio.ini environment)
// #define CS_MODE_CORE       // Public build with safety restrictions
// #define CS_MODE_INTERNAL   // Lab build with advanced features  

#define DEVELOPMENT_MODE 1    // Set to 0 for production builds

#if defined(CS_MODE_INTERNAL)
  #define INTERNAL_BUILD 1
#else
  #define INTERNAL_BUILD 0    // Default/Fallback profile
#endif

// =============================================================================
// 2. FEATURE FLAGS & SECURITY PROFILES
// =============================================================================
// #define ENABLE_ACTIVE_MITIGATION   1  // [FUTURE] Core mitigation engine (throttle/isolate)
// #define ENABLE_ANOMALY_DETECTION   1  // Already implemented via heuristics

#if INTERNAL_BUILD
  #define ENABLE_STRESS_SIM        1  // Stress simulations allowed in lab environment
  // #define DEFAULT_ARMED_STATE      true  // [FUTURE] Armed state by default for internal builds
#else
  #define ENABLE_STRESS_SIM        0  // Disabled in public Core builds
  // #define DEFAULT_ARMED_STATE      false  // [FUTURE] Disarmed state by default for core builds
#endif

// =============================================================================
// 3. DECISION THRESHOLDS (Scaled 0-10 for Dashboard JavaScript Matching)
// =============================================================================
// #define RISK_TOLERANCE             4  // [FUTURE] Lower = faster automated defenses
// #define T1_OBSERVE                 2  // [FUTURE]
// #define T2_NOTE                    4  // [FUTURE]
// #define T3_THROTTLE                6  // [FUTURE]
// #define T4_ISOLATE                 8  // [FUTURE] Trips dashboard high-threat metric
// #define T5_LOCKDOWN                10  // [FUTURE]

#define WINDOW_SIZE                100   // Sliding window size for feature extraction
// #define MAX_CLIENTS                50    // [FUTURE] Max tracked hardware nodes
#define LOG_ROTATE_DAYS            7     // SPIFFS log rotation cycle
// #define WATCHDOG_TIMEOUT_MS        1000  // [FUTURE] ML inference guardrail

// =============================================================================
// 4. HARDWARE GPIO PIN MAP (ESP32)
// =============================================================================
#define SNIFF_LED                  2
// #define PIN_LED_RED                17  // [FUTURE] RGB LED for threat status
// #define PIN_LED_GREEN              13  // [FUTURE]
// #define PIN_LED_BLUE               14  // [FUTURE]
// #define PIN_BUTTON                 15  // [FUTURE] Physical override button
// #define UNLOCK_PIN                 PIN_BUTTON  // [FUTURE]
// #define PIN_BUZZER                 16  // [FUTURE] Audio alert
// #define PIN_OLED_SDA               21  // [FUTURE] OLED display
// #define PIN_OLED_SCL               22  // [FUTURE]

// =============================================================================
// 5. NETWORK CONFIGURATION
// =============================================================================
// Wi-Fi Sniffer Configuration
#define WIFI_CHECK_INTERVAL_MS     30000  

// Fallback Captive Portal Access Point
#define AP_SSID                    "CyberSentinel-Fallback"
#define AP_PASS                    "fallback123456"
#define FALLBACK_AP_IP             IPAddress(192, 168, 4, 1)
// #define MAX_CONNECTIONS_NORMAL     4  // [FUTURE]

// =============================================================================
// 6. SPIFFS VIRTUAL FILE SYSTEM PATHS
// =============================================================================
// #define PATH_EVENTS_JSON           "/dashboard/dashboard.json"  // [FUTURE]
#define PATH_EVENTS_CSV            "/data.csv"
#define PATH_DASHBOARD_HTML        "/dashboard/dashboard.html"
#define PATH_DASHBOARD_CSS         "/dashboard/dashboard.css"
#define PATH_DASHBOARD_JS          "/dashboard/dashboard.js"
#define PATH_DASHBOARD_CHARTJS     "/dashboard/chart.min.js"

// =============================================================================
// 7. ARDUINO SYSTEM CONSTANTS & DELAYS
// =============================================================================
#define SERIAL_BAUD                115200
#define WEB_PORT                   80
#define MAX_BUFFER_SIZE            1024  // Protection against heap allocation crashes
// #define THROTTLE_DELAY_MS          10000  // [FUTURE] Length of association throttling
// #define ORIGINAL_PMF_ENABLED       0  // [FUTURE] Protected Management Frames baseline
#define LOG_INTERVAL_MS            30000 // Metrics flush rate
#define SWEEP_INTERVAL_MS          3000  // Radio blitz frequency in auto-hop mode
#define HOME_CHANNEL               1     // Channel the AP camps on between blitzes
#define THREAT_TIME_ELAPSED_MS     5000  // Time to dwell on a threat channel before returning home

// =============================================================================
// 8. CONSOLIDATED REPLAY & ANALYTICS ENGINE
// =============================================================================
// #define MAX_REPLAY_PACKETS         1000  // [FUTURE]
// #define MAX_PACKET_SIZE            256  // [FUTURE]
// #define REPLAY_MAX_PPS             200  // [FUTURE]
// #define REPLAY_MAX_DURATION_MS     60000  // [FUTURE]
#define FEATURE_WINDOW_MS          5000

// Memory Guardrails (Heap Safety Checkpoints)
#define MEMORY_WARNING_THRESHOLD   10000
// #define MEMORY_LOW_THRESHOLD       10000  // [DUPLICATE] Same as WARNING_THRESHOLD
#define MEMORY_CRITICAL_THRESHOLD  5000

// =============================================================================
// 9. CLOUD ENGINE & FIRMWARE OVER-THE-AIR (OTA) 
// =============================================================================
// ALL ARE [FUTURE] - Planned for V2 and V3
#define FW_VERSION                 "1.2.0"
// #define CLOUD_ENDPOINT             "https://your-railway-app.railway.app"
// #define WEBHOOK_URL                "https://your-webhook-endpoint.com/alert"

// #define DEFAULT_DEVICE_ID          "cs-int-01"
// #define DEFAULT_DEVICE_TOKEN       "cs-int-01"

// #define CLOUD_SYNC_INTERVAL        120000
// #define CLOUD_MAX_RETRIES          10
// #define CLOUD_TIMEOUT_MS           15000
// #define API_ERROR_THRESHOLD        5
// #define MAX_API_ERRORS             50

// #define OTA_BUFFER_SIZE            8192
// #define OTA_SHA256_BUFFER_SIZE     2048
// #define OTA_MAX_RETRIES            5

// System Cycle & Loop Intervals
// #define EVENT_THREAT_INTERVAL      10    // [FUTURE] Threat engine generation rate
// #define EVENT_WIFI_INTERVAL        7     // [FUTURE] Wi-Fi core event generation rate
#define HEARTBEAT_INTERVAL_MS      30000
#define RETRY_DELAY_MS             5000
#define MAX_RETRIES                5

// =============================================================================
// 10. THREAT PROFILE MODULAR CONFIGURATION
// =============================================================================

// Maps directly to ThreatLevel enum: THREAT_NONE=0, THREAT_LOW=1, THREAT_MEDIUM=2, THREAT_HIGH=3
static const char* const THREAT_CLASSIFICATIONS[] = {
    "SAFE",
    "WARNING",
    "RECONNAISSANCE", 
    "CRITICAL"
};

static const char* const THREAT_RECOMMENDATIONS[] = {
    "System secure. No anomalies detected.",
    "Monitor local RF interference or directional attackers.",
    "Verify network device authorization states.",
    "Isolate target device. Threat lock engaged."
};

// =============================================================================
// 11. SYSTEM RUNTIME INTERFACES
// =============================================================================
inline const char* getBuildModeStr() {
    #ifdef CS_MODE_CORE
        return "CORE";
    #elif defined(CS_MODE_INTERNAL)
        return "INTERNAL";
    #else
        return "CORE";
    #endif
}

#endif // CONFIG_H
