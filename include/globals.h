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
