#include "feature_extraction.h"
#include "types.h"
#include "config.h"
#include "logger.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <Arduino.h>

// =============================================================================
// STATIC MEMBER INITIALIZATION
// =============================================================================
FeatureExtraction* FeatureExtraction::instance = nullptr;

// =============================================================================
// CONSTRUCTOR
// =============================================================================
FeatureExtraction::FeatureExtraction(RadioIntake* radio) : radioIntake(radio) {
    windowSize = WINDOW_SIZE;
    packetWindow.clear();
    lastExtraction = 0;
    baseline = {};
}

FeatureExtraction* FeatureExtraction::getInstance(RadioIntake* radio) {
    static FeatureExtraction instanceStatic(radio);
    if (!instance) {
        instance = &instanceStatic;
    }
    return instance;
}

bool FeatureExtraction::initialize() {
    Serial.println("📊 Feature Extraction Engine Initializing...");
    Serial.println("✅ Feature Extraction Engine Ready (Zero-Heap Configuration)");
    return true;
}

// =============================================================================
// FEATURE EXTRACTION METHODS
// =============================================================================
void FeatureExtraction::processMetadata(const Metadata& meta) {
    packetWindow.push_back(meta);
    
    // Note: To maximize performance, ensure packetWindow is defined as a std::deque 
    // in feature_extraction.h so that pop_front() is an O(1) operation.
    if (packetWindow.size() > windowSize) {
        packetWindow.pop_front(); 
    }
}

FeatureVec FeatureExtraction::extractFeatures() {
    FeatureVec features = {};
    computeFeatures(features);
    return features;
}

void FeatureExtraction::updateBaseline(const FeatureVec& vec) {
    baseline = vec;
}

// =============================================================================
// FEATURE CALCULATION METHODS (Zero-Heap / Stack-Allocated Safeties)
// =============================================================================
float FeatureExtraction::calculateAvgRSSI() {
    if (packetWindow.empty()) return 0.0f;
    
    float sum = 0.0f;
    for (const auto& packet : packetWindow) {
        sum += packet.rssi;
    }
    return sum / packetWindow.size();
}

float FeatureExtraction::calculateRSSIStd() {
    if (packetWindow.size() < 2) return 0.0f;
    
    float avg = calculateAvgRSSI();
    float sumSquares = 0.0f;
    
    for (const auto& packet : packetWindow) {
        float diff = packet.rssi - avg;
        sumSquares += diff * diff;
    }
    
    return sqrt(sumSquares / (packetWindow.size() - 1));
}

float FeatureExtraction::calculatePacketRate(unsigned long now) {
    if (packetWindow.size() < 2) return 0.0f;
    
    unsigned long timeSpan = packetWindow.back().ts - packetWindow.front().ts;
    if (timeSpan == 0) timeSpan = 1; 
    
    return (packetWindow.size() * 1000.0f) / timeSpan;
}

// Stack-allocated tracking loop replaces std::map
float FeatureExtraction::calculateMACEntropy() {
    size_t totalPackets = packetWindow.size();
    if (totalPackets == 0) return 0.0f;
    
    // Allocate fixed arrays on the stack based on maximum constraint thresholds
    uint32_t uniqueMacs[WINDOW_SIZE];
    int macCounts[WINDOW_SIZE] = {0};
    int uniqueCount = 0;
    
    // Populating parallel arrays purely on the stack
    for (const auto& packet : packetWindow) {
        bool found = false;
        for (int i = 0; i < uniqueCount; i++) {
            if (uniqueMacs[i] == packet.hashed_src_mac) {
                macCounts[i]++;
                found = true;
                break;
            }
        }
        if (!found && uniqueCount < WINDOW_SIZE) {
            uniqueMacs[uniqueCount] = packet.hashed_src_mac;
            macCounts[uniqueCount] = 1;
            uniqueCount++;
        }
    }
    
    float entropy = 0.0f;
    float total = totalPackets;
    
    for (int i = 0; i < uniqueCount; i++) {
        float probability = macCounts[i] / total;
        if (probability > 0) {
            entropy -= probability * log2(probability);
        }
    }
    return entropy;
}

// Stack-allocated tracking loop replaces std::map
float FeatureExtraction::calculateChannelDiversity() {
    if (packetWindow.empty()) return 0.0f;
    
    bool channelSeen[16] = {false};
    int uniqueChannels = 0;
    
    for (const auto& packet : packetWindow) {
        if (packet.channel >= 1 && packet.channel <= 14) {
            if (!channelSeen[packet.channel]) {
                channelSeen[packet.channel] = true;
                uniqueChannels++;
            }
        }
    }
    
    return (float)uniqueChannels;
}

// Single-Pass Mathematical Variance calculation eliminates std::vector heap usage
float FeatureExtraction::calculateTimeVariance() {
    size_t totalPackets = packetWindow.size();
    if (totalPackets < 2) return 0.0f;
    
    size_t numDeltas = totalPackets - 1;
    float sumDeltas = 0.0f;
    float sumSqDeltas = 0.0f;
    
    for (size_t i = 1; i < totalPackets; ++i) {
        float delta = (float)(packetWindow[i].ts - packetWindow[i-1].ts);
        sumDeltas += delta;
        sumSqDeltas += delta * delta;
    }
    
    // Mathematical single-pass variance formula
    float variance = (sumSqDeltas - (sumDeltas * sumDeltas) / numDeltas) / numDeltas;
    return (variance < 0.0f) ? 0.0f : variance;
}

// =============================================================================
// MATHEMATICAL ENGINE EVALUATION UNIT
// =============================================================================
void FeatureExtraction::computeFeatures(FeatureVec& vec) {
    unsigned long now = millis();

    if (packetWindow.size() < FEATURE_MIN_PACKETS) {
        vec.avg_rssi = -95.0f; 
        vec.rssi_variance = 0.0f;
        vec.assoc_rate = 0.0f;
        vec.disassoc_rate = 0.0f;
        vec.mac_entropy = 0.0f;
        vec.channel_entropy = 0.0f;
        vec.timing_jitter = 0.0f;
        vec.beacon_density = 0.0f;
        vec.packet_loss_rate = 0.0f;
        vec.peak_channel = 1;
        
        lastExtraction = now;
        return;
    }

    unsigned long timeDelta = packetWindow.back().ts - packetWindow.front().ts;
    if (timeDelta == 0) timeDelta = 1; 
    float timeSpanSec = timeDelta / 1000.0f;

    int deauthCount = 0;
    int beaconCount = 0;

    int channelVolume[MAX_CHANNELS] = {0}; 
    int maxPacketsOnChannel = 0;
    int primaryOffendingChannel = packetWindow.front().channel;
    
    for (const auto& packet : packetWindow) {
        if (packet.channel >= 1 && packet.channel <= 14) {
            channelVolume[packet.channel]++;
            if (channelVolume[packet.channel] > maxPacketsOnChannel) {
                maxPacketsOnChannel = channelVolume[packet.channel];
                primaryOffendingChannel = packet.channel;
            }
        }

        if (packet.frame_type == 0) { // Management Frames
            if (packet.subtype == 12 || packet.subtype == 10) {
                deauthCount++;
            } else if (packet.subtype == 8) {
                beaconCount++;
            }
        }
    }
    
    vec.avg_rssi = calculateAvgRSSI();
    
    // Optimized single-pass variance calculation
    float avgRssiSnapshot = vec.avg_rssi;
    float sumSquares = 0.0f;
    for (const auto& packet : packetWindow) {
        float diff = packet.rssi - avgRssiSnapshot;
        sumSquares += diff * diff;
    }
    vec.rssi_variance = sqrt(sumSquares / (packetWindow.size() - 1));
    
    vec.assoc_rate = calculatePacketRate(now);
    vec.disassoc_rate = deauthCount / timeSpanSec;
    vec.beacon_density = beaconCount / timeSpanSec;
    
    vec.mac_entropy = calculateMACEntropy();
    vec.channel_entropy = calculateChannelDiversity();
    vec.timing_jitter = calculateTimeVariance();
    vec.packet_loss_rate = 0.0f;
    vec.peak_channel = primaryOffendingChannel;
    
    // Bounds clamping structures
    vec.avg_rssi = constrain(vec.avg_rssi, (float)RSSI_MIN, (float)RSSI_MAX);
    vec.rssi_variance = max(0.0f, vec.rssi_variance);
    vec.assoc_rate = max(0.0f, vec.assoc_rate);
    vec.mac_entropy = constrain(vec.mac_entropy, 0.0f, MAC_ENTROPY_MAX);
    vec.channel_entropy = constrain(vec.channel_entropy, 0.0f, CHANNEL_ENTROPY_MAX);
    vec.timing_jitter = max(0.0f, vec.timing_jitter);
    vec.beacon_density = max(0.0f, vec.beacon_density);

    lastExtraction = now;
}