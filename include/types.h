#ifndef TYPES_H
#define TYPES_H

#include <Arduino.h>

// 802.11 frame subtype markers (used by packet parser + detector)
#define BEACON_FRAME 0x08
#define DEAUTH_FRAME 0x0C

// =============================================================================
// LOGGING ENUMS
// =============================================================================
enum LogLevel {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_CRITICAL
};

enum LogCategory {
    CAT_SYSTEM,
    CAT_SECURITY,
    CAT_PERFORMANCE,
    CAT_NETWORK,
    CAT_MEMORY,
    CAT_APPLICATION
};

// =============================================================================
// STRUCTURED LOG ENTRY
// =============================================================================
struct LogEntry {
    unsigned long timestamp;
    LogLevel        level;
    LogCategory     category;
    String          component;
    String          message;
    size_t          memoryUsage;
    String          context;
};

// Health flags for each subsystem (read by /system and heartbeat)
struct ComponentStatus {
    bool wifiConnected              = false;
    bool spiffsInitialized          = false;
    bool webServerStarted           = false;
    bool radioInitialized           = false;
    bool featureExtractorInitialized = false;
    bool threatAnalyzerInitialized  = false;
    bool loggerInitialized          = false;
};

// =============================================================================
// PACKET PIPELINE
// =============================================================================
// One captured frame, normalized for the FreeRTOS queue.
// Everything here is ISR-safe (no heap, plain old data).
struct Metadata {
    unsigned long ts;          // capture time (ms)
    uint32_t      hashed_src_mac;
    uint32_t      hashed_dst_mac;
    int           rssi;
    int           channel;
    uint8_t       frame_type;
    uint16_t      length;
    float         beacon_interval;
    uint8_t       mac[6];
    char          ssid[33];
    uint8_t       subtype;
};

// Aggregated features computed over a FEATURE_WINDOW_MS sliding window.
struct FeatureVec {
    float assoc_rate;
    float disassoc_rate;
    float avg_rssi;
    float rssi_variance;
    float beacon_density;
    float mac_entropy;
    float timing_jitter;
    float channel_entropy;
    float packet_loss_rate;
    int   peak_channel;
};
typedef FeatureVec Features;

// =============================================================================
// THREAT ENGINE OUTPUTS
// =============================================================================
enum ThreatLevel {
    THREAT_NONE,
    THREAT_LOW,
    THREAT_MEDIUM,
    THREAT_HIGH
};

// Verdict from ThreatAnalyzer — all strings live in flash (PROGMEM-equivalent
// char pointers) to avoid heap fragmentation under high telemetry load.
struct ThreatReport {
    ThreatLevel   level;
    float         threat_score;
    const char*   classification;  // "SAFE" / "WARNING" / "RECONNAISSANCE" / "CRITICAL"
    const char*   attack_type;     // e.g. "Deauthentication Flood"
    const char*   recommendation;  // remediation advice
    unsigned long timestamp;
    int           offending_channel;
};

// Structured CSV/exportable event record. Fixed-size notes buffer avoids malloc.
struct Event {
    unsigned long timestamp;
    uint32_t      trace_id;
    const char*   event_type;
    FeatureVec    features;
    float         threat_score;
    const char*   classification;
    const char*   pre_state;
    const char*   post_state;
    const char*   recommendation;
    char          notes[64];
};

#endif // TYPES_H
