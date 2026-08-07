#ifndef GLOBALS_H
#define GLOBALS_H

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "types.h"

// Radio sweep mode — drives the Core 0 Guerilla Sweep controller
enum ChannelMode {
    MODE_AUTO_HOP,
    MODE_MANUAL,
    MODE_THREAT_LOCK
};

// =============================================================================
// RECOMMENDATION ENGINE — LRU RING BUFFER (4 entries)
// =============================================================================
enum RecSeverity {
    REC_INFO,
    REC_SUGGEST,
    REC_WARN
};

enum RecParameter {
    REC_PARAM_DEAUTH,
    REC_PARAM_ASSOC,
    REC_PARAM_RSSI_VAR
};

struct RecEntry {
    unsigned long timestamp;
    RecSeverity   severity;
    RecParameter  parameter;
    float         from_value;
    float         to_value;
    char          reason[96];
};

struct EventSummary {
    bool          present;
    unsigned long timestamp;
    char          classification[16];
    char          attack_type[32];
    char          recommendation[96];
    char          source[16];
    float         threat_score;
    int           channel;
    unsigned long duration_ms;
};

// =============================================================================
// INTER-CORE STATE (externs — memory lives in globals.cpp)
// =============================================================================
// Core 0 (radio controller) and Core 1 (everything else) share these through
// `globalStateMutex`. ALWAYS take the mutex before read+write from Core 1.
extern ComponentStatus systemStatus;
extern FeatureVec      currentFeatures;
extern ThreatReport    currentThreatReport;
extern unsigned long   lastFeatureUpdate;
extern float           currentThreatScore;
extern String          currentClassification;
extern bool            mitigationActive;
extern unsigned long   lastLogTime;
extern int             eventCount;
extern EventSummary    latestEventSummary;

extern ChannelMode currentChannelMode;
extern uint8_t     currentChannel;
extern uint8_t     targetedThreatChannel;
extern unsigned long lastThreatSeenTime;

extern volatile bool stressTestActive;
extern volatile unsigned long stressTestInjectedPackets;
extern volatile unsigned long stressTestStartTime;

// Runtime-tunable Stress Test config. Dashboard can override every field via
// the /stresstest query params. Zero values fall back to config.h defaults.
extern volatile uint32_t stressCfgRatePktPerSec;    // target injection rate
extern volatile uint8_t  stressCfgAttackProfile;    // 0..3 (see config.h)
extern volatile uint8_t  stressCfgFrameTypeMask;    // bitmask: bit0=deauth 1=disassoc 2=assoc 3=probe
extern volatile int8_t   stressCfgRssiMin;          // dBm
extern volatile int8_t   stressCfgRssiMax;          // dBm
extern volatile uint8_t  stressCfgMacRandomize;     // 1 = randomize per pkt (tests entropy)
extern volatile uint32_t stressCfgBurstOnMs;        // BURSTY profile on-time
extern volatile uint32_t stressCfgBurstOffMs;       // BURSTY profile off-time
extern volatile uint32_t stressCfgMicroburstOnMs;   // MICROBURST profile on-time
extern volatile uint32_t stressCfgMicroburstOffMs;  // MICROBURST profile off-time
extern volatile uint8_t  stressCfgSpreadChannels;   // 1 = vary channel ±2
extern volatile uint32_t stressCfgLoopIterationMs;  // outer loop cadence

// Runtime-tunable Detection Thresholds (config.h as compile-time defaults,
// persisted to NVS, settable via /config endpoint).
extern volatile float detectCfgDeauthThreshold;
extern volatile float detectCfgAssocThreshold;
extern volatile float detectCfgRssiVarThreshold;

// Recommendation Ring Buffer (4-entry LRU)
#define REC_RING_SIZE 4
extern RecEntry recRing[REC_RING_SIZE];
extern volatile uint8_t recRingHead;
extern volatile uint8_t recRingCount;

// Baseline drift detector state
extern float baselineAvgDeauth;
extern float baselineAvgAssoc;
extern float baselineAvgRssiVar;
extern unsigned long baselineFalseWarningCount[3]; // per-param false warning count
extern unsigned long baselineSampleCount;

// Single mutex for all shared state. Timeout-gated everywhere to avoid deadlock.
extern SemaphoreHandle_t globalStateMutex;

// =============================================================================
// RUNTIME HELPERS
// =============================================================================
void   initializeGlobals();
void   resetSystemState();
String getSystemStatusJson();
bool   checkSystemHealth();

// NVS persistence for detection thresholds
bool   nvsLoadThresholds();
bool   nvsSaveThresholds();
void   nvsResetThresholdsToDefaults();

// Recommendation ring buffer helpers
void   recPush(const RecEntry& entry);
RecEntry recGet(uint8_t index); // 0 = newest, recRingCount-1 = oldest
String recSeverityStr(RecSeverity s);
String recParamStr(RecParameter p);

// Recommendation source generators
void   recCheckBaselineDrift();
void   recCheckLiveThreatResponse(const ThreatReport& report, const FeatureVec& features);

// Effective-value helpers (falls back to config.h defaults if globals are 0 sentinel)
float  effDeauthThreshold();
float  effAssocThreshold();
float  effRssiVarThreshold();

#endif // GLOBALS_H
