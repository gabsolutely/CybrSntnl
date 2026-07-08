#ifndef GLOBALS_H
#define GLOBALS_H

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "types.h"

enum ChannelMode {
    MODE_AUTO_HOP,      
    MODE_MANUAL,        
    MODE_THREAT_LOCK    
};

// =============================================================================
// INTER-CORE STATE VARIABLES (Marked extern for linking accuracy)
// =============================================================================
extern ComponentStatus systemStatus;
extern FeatureVec currentFeatures;
extern ThreatReport currentThreatReport;
extern unsigned long lastFeatureUpdate;
extern float currentThreatScore;
extern String currentClassification;
extern bool mitigationActive;
extern unsigned long lastLogTime;
extern int eventCount;

extern ChannelMode currentChannelMode;
extern uint8_t currentChannel;
extern uint8_t targetedThreatChannel;
extern unsigned long lastThreatSeenTime;

// Shared Mutex to safely pass variables between Radio (Core 0) and Dashboard (Core 1)
extern SemaphoreHandle_t globalStateMutex;

// Core Runtime Routines
void initializeGlobals();
void resetSystemState();
String getSystemStatusJson();
bool checkSystemHealth();

#endif // GLOBALS_H