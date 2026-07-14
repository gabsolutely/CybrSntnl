#ifndef TYPES_H
#define TYPES_H

#include <Arduino.h>

// Wi-Fi Core Frame Identifiers
#define BEACON_FRAME 0x08
#define DEAUTH_FRAME 0x0C
// #define PROBE_REQ_FRAME 0x04  // [FUTURE]
// #define PROBE_RESP_FRAME 0x05  // [FUTURE]

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
// LOG ENTRY SCHEMA
// =============================================================================
struct LogEntry {
    unsigned long timestamp;
    LogLevel level;
    LogCategory category;
    String component;
    String message;
    size_t memoryUsage;
    String context;
};

// Structure to hold the status of various system components
struct ComponentStatus {
    bool wifiConnected = false;
    bool spiffsInitialized = false;
    bool webServerStarted = false;
    bool radioInitialized = false;
    bool featureExtractorInitialized = false;
    bool threatAnalyzerInitialized = false;
    // bool responsePolicyInitialized = false;  // [FUTURE]
    bool loggerInitialized = false;
};

// Structure to hold metadata for each captured packet
struct Metadata {
    unsigned long ts;
    uint32_t hashed_src_mac;   
    uint32_t hashed_dst_mac;   
    int rssi;
    int channel;
    uint8_t frame_type;
    uint16_t length;
    float beacon_interval;
    uint8_t mac[6];  
    char ssid[33];             
    uint8_t subtype;  
};

// Structure to hold extracted features from a sliding window of packets
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
    int peak_channel;
};

typedef FeatureVec Features;

enum ThreatLevel {
    THREAT_NONE,
    THREAT_LOW,
    THREAT_MEDIUM,
    THREAT_HIGH
};

// Swapped out dynamic String heap spaces for static character pointers where data relies on fixed log literals
struct ThreatReport {
    ThreatLevel level;
    float threat_score;       
    const char* classification; // e.g., "SAFE", "LOW", "CRITICAL" (Points to flash memory string literals)
    const char* attack_type;    // e.g., "Deauth Flood", "Rogue AP", "None"
    const char* recommendation; // e.g., "Enable PMF"
    unsigned long timestamp;
    int offending_channel;
};

// Optimized event logging properties to limit dynamic heap usage over high telemetry rates
struct Event {
    unsigned long timestamp;
    uint32_t trace_id;          // Converted from String to lightweight numeric tracking ID
    const char* event_type;     // Converted to efficient flash string pointer
    FeatureVec features;
    float threat_score;
    const char* classification; 
    const char* pre_state;     
    const char* post_state;    
    // uint32_t replay_id;      // [FUTURE]
    const char* recommendation; // Flattened single recommendations pointer to bypass costly std::vector copies
    char notes[64];             // Replaced dynamic String with static buffer constraint
    // float effect;            // [FUTURE]
};



#endif // TYPES_H
