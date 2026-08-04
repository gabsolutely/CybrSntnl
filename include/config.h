/*
 * ===============================================================================
 * ESP CYBER SENTINEL - CONFIGURATION HEADER
 * ===============================================================================
 * VERSION: 1.2.0 (Refactored & De-gunked)
 * ===============================================================================
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <cstddef> // For size_t

// =============================================================================
// 1. BUILD MODE & TARGET FLAGS
// =============================================================================
// Uncomment your target build profile (or handle via platformio.ini environment)
// #define CS_MODE_CORE       // Public build with safety restrictions
// #define CS_MODE_INTERNAL   // Lab build with advanced features  

#define DEVELOPMENT_MODE 0    // Set to 0 for production builds

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

// Dashboard Web Authentication (HTTP Basic Auth)
// CHANGE THESE BEFORE DEPLOYING IN ANY UNTRUSTED ENVIRONMENT
#define DASH_AUTH_USER             "admin"
#define DASH_AUTH_PASS             "cybersentinel"
#define DASH_AUTH_ENABLED          1    // Set to 0 to disable auth (NOT recommended)

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

// Attack type configurations with tailored recommendations
struct AttackProfile {
    const char* attack_type;
    const char* recommendation;
};

static const AttackProfile ATTACK_PROFILES[] = {
    {"High Traffic Volume",                  "Deploy packet throttling and rate limiting protocols."},
    {"Deauthentication Flood",               "Enable 802.11w Protected Management Frames (PMF) on AP."},
    {"MAC Spoofing / Assoc Flood",           "Enable 802.11w Protected Management Frames (PMF) and MAC filtering."},
    {"Signal Instability / Jamming Attempt", "Trigger frequency hopping or shift critical telemetry channels."},
    {"Normal",                               "System secure. No anomalies detected."}
};

// Helper to get number of attack profiles
static constexpr size_t ATTACK_PROFILES_COUNT = sizeof(ATTACK_PROFILES) / sizeof(ATTACK_PROFILES[0]);

// Threat detection thresholds
static constexpr float DEAUTH_THRESHOLD = 2.0f;       // Deauth packets per second
static constexpr float ASSOC_THRESHOLD = 100.0f;     // Assoc packets per second
static constexpr float RSSI_VARIANCE_THRESHOLD = 15.0f; // RSSI variance threshold

// Feature extraction constants
#define FEATURE_MIN_PACKETS          5     // Minimum packets needed in window to extract features
#define MAX_CHANNELS                 15    // Maximum number of channels to track
#define RSSI_MIN                     -100  // Minimum RSSI value (dBm)
#define RSSI_MAX                     0     // Maximum RSSI value (dBm)
#define MAC_ENTROPY_MAX              8.0f  // Maximum MAC entropy value
#define CHANNEL_ENTROPY_MAX          14.0f // Maximum channel entropy/diversity

// Radio intake constants
#define MAX_PACKETS_PER_CYCLE        200   // Max packets to process per radio intake cycle
#define RADIO_OUTPUT_INTERVAL_MS     2000  // Interval for radio output to Serial
#define QUEUE_WARNING_THRESHOLD      0.8f  // Queue fill percentage to trigger warning
#define QUEUE_WARNING_INTERVAL_MS    5000  // Interval between queue warnings

// Dashboard constants
#define MUTEX_TIMEOUT_MS             20    // Mutex timeout for global state access (ms)
#define EMA_WEIGHT                   0.1f  // Exponential Moving Average weight for threat/entropy
#define HIGH_THREAT_THRESHOLD        7.0f  // Threshold for high-threat alerts
#define CSV_MUTEX_TIMEOUT_MS         50    // Mutex timeout for CSV generation

// Logger constants
#define MAX_LOG_ENTRIES              1000  // Maximum log entries before rotation

// SPIFFS dashboard file validation thresholds
#define DASHBOARD_HTML_MIN_SIZE      1000  // Minimum size for valid dashboard.html
#define DASHBOARD_CSS_MIN_SIZE       100   // Minimum size for valid dashboard.css
#define DASHBOARD_JS_MIN_SIZE        1000  // Minimum size for valid dashboard.js



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
