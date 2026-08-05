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

extern ChannelMode currentChannelMode;
extern uint8_t     currentChannel;
extern uint8_t     targetedThreatChannel;
extern unsigned long lastThreatSeenTime;

extern volatile bool stressTestActive;
extern volatile unsigned long stressTestInjectedPackets;

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

// Single mutex for all shared state. Timeout-gated everywhere to avoid deadlock.
extern SemaphoreHandle_t globalStateMutex;

// =============================================================================
// RUNTIME HELPERS
// =============================================================================
void   initializeGlobals();
void   resetSystemState();
String getSystemStatusJson();
bool   checkSystemHealth();

#endif // GLOBALS_H
