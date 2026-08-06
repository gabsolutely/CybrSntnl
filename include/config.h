/*
 * ===============================================================================
 * ESP CYBER SENTINEL - CONFIGURATION HEADER
 * ===============================================================================
 * VERSION: 1.3.0 (Hardened Semi-Production)
 * ===============================================================================
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <cstddef>

// =============================================================================
// 1. BUILD MODE
// =============================================================================
// CS_MODE_CORE     / CS_MODE_INTERNAL are set via platformio.ini build flags.
// Do NOT uncomment them here — the build system handles them per env.

#define FW_VERSION                 "1.4.0"
#define DEVELOPMENT_MODE 0    // 0 = release (clean logs, no debug spam)

#if defined(CS_MODE_INTERNAL)
  #define INTERNAL_BUILD 1
#else
  #define INTERNAL_BUILD 0    // Default: public Core build
#endif

// =============================================================================
// 2. FEATURE FLAGS
// =============================================================================
// Active mitigation, AI/ML, rogue AP detection = planned V2/V3.
// Heuristic anomaly detection IS implemented (see ThreatAnalyzer).

#if INTERNAL_BUILD
  #define ENABLE_STRESS_SIM    1   // Lab-only: fake packet injector for demos
#else
  #define ENABLE_STRESS_SIM    0   // Disabled in public builds
#endif

// =============================================================================
// 3. DETECTION TUNING
// =============================================================================
// ⚠️  CRITICAL NOTE ON TUNING ⚠️
//   These values are lab-defaults for a quiet residential environment. They
//   WILL FALSE-POSITIVE in busy venues (conferences, LAN parties, coffee
//   shops, university dorms). There is no one-size-fits-all:
//     • DEAUTH_THRESHOLD   → 2 pkt/s is aggressive for a lab, 20 pkt/s is
//                            typical for a conference.
//     • ASSOC_THRESHOLD    → 100 pkt/s is safe for residential, 800+ in
//                            event Wi-Fi with 50+ clients.
//     • RSSI_VARIANCE_THRESHOLD → 15 is tight, use 25+ in RF-dense areas.
//     • HIGH_THREAT_THRESHOLD → 7.0 triggers Threat Lock. Bump to 8.0/8.5
//                               if a crowded room is enough to spike it.
//   For portfolio demos use Stress Test's "MICROBURST DEAUTH" profile at
//   120 pkt/s — it's the most realistic replica of a handshake-grabber.
// =============================================================================
#define WINDOW_SIZE                100   // Feature-extraction sliding window
#define LOG_ROTATE_DAYS            7     // SPIFFS log rotation cycle

// Detection thresholds — TUNE PER ENVIRONMENT (see warning above)
static constexpr float DEAUTH_THRESHOLD        = 2.0f;   // pkt/s → disassoc flood
static constexpr float ASSOC_THRESHOLD         = 100.0f; // pkt/s → assoc/spoof flood
static constexpr float RSSI_VARIANCE_THRESHOLD = 15.0f;  // variance → jam/instability

#define FEATURE_MIN_PACKETS        5     // Min packets needed to score a window
#define HIGH_THREAT_THRESHOLD      7.0f  // Threat score → auto Threat Lock + alert

// =============================================================================
// 3B. STRESS TEST / SYNTHETIC INJECTOR CONFIG
// =============================================================================
// These are *compile-time defaults*. At runtime the dashboard can override
// every value via the /stresstest endpoint query params. Zero values fall
// back to the defaults below.
//
//   Stress attack profiles (attack_profile):
//     0 = CONSTANT_STREAM      — flat line, easiest to reproduce
//     1 = BURSTY_SQUARE        — 3s on / 1s off square wave
//     2 = MICROBURST_DEAUTH    — the realistic attacker. ~1.2s inject, ~4s
//                                silence loop. Exactly what a handshake grabber does.
//     3 = MIXED_FRAME_TYPES    — deauth + assoc + probe-request mix for
//                                testing the RSSI/entropy features.
//
//   Frame-type flags (frame_type_mask, bitmask; combine via OR):
//     bit 0 (1)  → Deauth (subtype 0x0C)
//     bit 1 (2)  → Disassoc (subtype 0x0A)
//     bit 2 (4)  → Assoc Request (subtype 0x00)
//     bit 3 (8)  → Probe Request (subtype 0x04)
//
//   Recommended demo presets (copy-paste into URL or dashboard):
//     • "easy handshake grabber"   → rate=120, profile=2 (MICROBURST), mask=1
//     • "noisy coffee shop"        → rate=450, profile=0, mask=15, rssi_min=-75, rssi_max=-35, entropy=1
//     • "classroom safe baseline"  → rate=30,  profile=0, mask=1

#define STRESS_DEFAULT_RATE_PKTS_PER_SEC   50     // Target packets/sec
#define STRESS_DEFAULT_ATTACK_PROFILE      0      // 0..3 (see above)
#define STRESS_DEFAULT_FRAME_TYPE_MASK     1      // default = deauth only (bit 0)
#define STRESS_DEFAULT_RSSI_MIN            -85    // dBm
#define STRESS_DEFAULT_RSSI_MAX            -40    // dBm
#define STRESS_DEFAULT_MAC_RANDOMIZE       0      // 1 = randomize hashes (tests entropy)
#define STRESS_DEFAULT_BURST_ON_MS         3000   // BURSTY_SQUARE profile → on-time
#define STRESS_DEFAULT_BURST_OFF_MS        1000   // BURSTY_SQUARE profile → off-time
#define STRESS_DEFAULT_MICROBURST_ON_MS    1200   // MICROBURST_DEAUTH → on-time
#define STRESS_DEFAULT_MICROBURST_OFF_MS   4000   // MICROBURST_DEAUTH → off-time
#define STRESS_DEFAULT_SPREAD_CHANNELS     0      // 1 = vary channel across home±2
#define STRESS_DEFAULT_LOOP_ITERATION_MS   1000   // outer loop cadence

// =============================================================================
// 4. HARDWARE
// =============================================================================
#define SNIFF_LED                  2     // Activity indicator (GPIO 2 = onboard LED on most devkits)

// Optional expansion pins (uncomment and wire up as needed):
// RGB threat status  : PIN_LED_RED=17, PIN_LED_GREEN=13, PIN_LED_BLUE=14
// Override button    : PIN_BUTTON=15
// Buzzer alert       : PIN_BUZZER=16
// OLED 128x64 (SSD1306 I2C): PIN_OLED_SDA=21, PIN_OLED_SCL=22

// =============================================================================
// 5. NETWORK & AUTH
// =============================================================================
// ⚠️ CHANGE THESE BEFORE FLASHING IN ANY UNTRUSTED ENVIRONMENT ⚠️

// Standalone access point (dashboard UI lives here)
#define WIFI_CHECK_INTERVAL_MS     30000
#define AP_SSID                    "CyberSentinel-AP"
#define AP_PASS                    "fallback123456"
#define FALLBACK_AP_IP             IPAddress(192, 168, 4, 1)

// Dashboard HTTP Basic Auth
#define DASH_AUTH_USER             "admin"
#define DASH_AUTH_PASS             "cybersentinel"
#define DASH_AUTH_ENABLED          1    // 0 = DISABLE (not recommended)

// =============================================================================
// 6. SPIFFS FILE PATHS
// =============================================================================
#define PATH_EVENTS_CSV            "/data.csv"
#define PATH_DASHBOARD_HTML        "/dashboard/dashboard.html"
#define PATH_DASHBOARD_CSS         "/dashboard/dashboard.css"
#define PATH_DASHBOARD_JS          "/dashboard/dashboard.js"
#define PATH_DASHBOARD_CHARTJS     "/dashboard/chart.min.js"

#define DASHBOARD_HTML_MIN_SIZE    1000  // Integrity check: below this → corrupt SPIFFS upload
#define DASHBOARD_CSS_MIN_SIZE     100
#define DASHBOARD_JS_MIN_SIZE      1000

// =============================================================================
// 7. SYSTEM TIMING & MEMORY
// =============================================================================
#define SERIAL_BAUD                115200
#define WEB_PORT                   80
#define MAX_BUFFER_SIZE            1024  // FreeRTOS packet queue depth

#define LOG_INTERVAL_MS            30000 // Metrics flush
#define SWEEP_INTERVAL_MS          3000  // Guerilla blitz cadence
#define HOME_CHANNEL               1     // AP anchor (dashboard channel)
#define THREAT_TIME_ELAPSED_MS     5000  // Threat-Lock cool-down

#define FEATURE_WINDOW_MS          5000  // Feature engine re-score interval

#define MEMORY_WARNING_THRESHOLD   10000 // Heap low-water → log warning
#define MEMORY_CRITICAL_THRESHOLD  5000  // Heap critical → throttle tasks

#define HEARTBEAT_INTERVAL_MS      30000
#define RETRY_DELAY_MS             5000
#define MAX_RETRIES                5

// =============================================================================
// 8. THREAT CLASSIFICATION TABLES
// =============================================================================
// Index maps 1:1 with ThreatLevel enum (0..3)
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

// Attack-type → specific remediation (matched from the detection engine)
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
static constexpr size_t ATTACK_PROFILES_COUNT = sizeof(ATTACK_PROFILES) / sizeof(ATTACK_PROFILES[0]);

// =============================================================================
// 9. FEATURE EXTRACTOR CONSTANTS
// =============================================================================
#define MAX_CHANNELS                 15
#define RSSI_MIN                     -100
#define RSSI_MAX                     0
#define MAC_ENTROPY_MAX              8.0f
#define CHANNEL_ENTROPY_MAX          14.0f

// Radio intake (Core 0 packet pipeline)
#define MAX_PACKETS_PER_CYCLE        200
#define RADIO_OUTPUT_INTERVAL_MS     2000
#define QUEUE_WARNING_THRESHOLD      0.8f
#define QUEUE_WARNING_INTERVAL_MS    5000

// Dashboard glue (inter-core sync weights)
#define MUTEX_TIMEOUT_MS             20
#define EMA_WEIGHT                   0.1f   // 10% new, 90% history → smooth threat curves
#define CSV_MUTEX_TIMEOUT_MS         50

// Logger
#define MAX_LOG_ENTRIES              1000

// =============================================================================
// 10. RUNTIME HELPERS
// =============================================================================
inline const char* getBuildModeStr() {
    #ifdef CS_MODE_INTERNAL
        return "INTERNAL";
    #else
        return "CORE";
    #endif
}

#endif // CONFIG_H
