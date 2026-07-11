#include "threat_analyzer.h"
#include <Arduino.h>
#include <algorithm> // For std::min and std::max
#include "config.h"  // Pulls in THREAT_CLASSIFICATIONS / THREAT_RECOMMENDATIONS arrays

ThreatReport ThreatAnalyzer::analyzeEnvironment(const FeatureVec& features) {
    ThreatReport report;
    report.timestamp = millis();
    
    static float last_smoothed_score = 1.0f;
    const float ALPHA = 0.3f; 

    float dynamic_score = 1.0f;
    const char* detected_type = "Normal";

    // =========================================================================
    // EVALUATION ENGINE (Core Heuristics)
    // =========================================================================
    
    // 1. Deauthentication Attack Detection
    // Standard networks rarely see more than 1-2 legitimate deauths per second.
    if (features.disassoc_rate > 2.0f) { 
        float deauth_penalty = std::min(5.0f, features.disassoc_rate * 1.5f);
        dynamic_score += deauth_penalty;
        
        if (deauth_penalty > 3.0f) {
            detected_type = "Deauthentication Flood";
        }
    }

    // 2. Association Flood / MAC Spoofing Detection
    if (features.assoc_rate > 100.0f) {
        float velocity_penalty = std::min(6.0f, (features.assoc_rate - 100.0f) * 0.02f);
        float spoofing_penalty = std::min(3.0f, features.mac_entropy * 0.5f);
        
        dynamic_score += (velocity_penalty + spoofing_penalty);
        
        // Use strcmp to prevent overwriting a higher-priority Deauth alert unless severe
        if (spoofing_penalty > 1.5f) {
            detected_type = "MAC Spoofing / Assoc Flood";
        } else if (velocity_penalty > 2.0f && strcmp(detected_type, "Normal") == 0) {
            detected_type = "High Traffic Volume";
        }
    } 
    
    // 3. Signal Jamming / Interference Detection
    if (features.rssi_variance > 15.0f) {
        float jamming_penalty = std::min(3.0f, (features.rssi_variance - 15.0f) * 0.15f);
        dynamic_score += jamming_penalty;
        
        if (jamming_penalty > 1.5f && dynamic_score < 7.0f && strcmp(detected_type, "Normal") == 0) {
            detected_type = "Signal Instability / Jamming Attempt";
        }
    }

    // =========================================================================
    // MATH PIPELINE FILTER PASS
    // =========================================================================
    float raw_capped_score = std::min(10.0f, dynamic_score);

    // If airspace is quiet (very low packet rate and low RSSI = noise floor)
    if (features.assoc_rate < 2.0f && features.avg_rssi <= -85.0f) {
        raw_capped_score = 1.0f; 
        detected_type = "Normal";
    }
    
    // Exponential Moving Average (EMA) - Smooths UI rendering and prevents jitter
    float smoothed_score = (ALPHA * raw_capped_score) + ((1.0f - ALPHA) * last_smoothed_score);
    last_smoothed_score = smoothed_score;
    report.threat_score = smoothed_score;

    // =========================================================================
    // SEVERITY MAPPING
    // =========================================================================
    if (report.threat_score >= 7.0f) {
        report.level = THREAT_HIGH;
    } 
    else if (report.threat_score >= 5.0f) { 
        report.level = THREAT_MEDIUM;
    }
    else if (report.threat_score >= 2.5f) { 
        report.level = THREAT_LOW; 
    } 
    else {
        report.level = THREAT_NONE;
    }

    // Assign modular fields from config/types structures
    report.classification = THREAT_CLASSIFICATIONS[report.level];
    report.attack_type = detected_type;
    report.offending_channel = features.peak_channel;

    // Setup basic level-based default fallback recommendation
    report.recommendation = THREAT_RECOMMENDATIONS[report.level];

    // =========================================================================
    // DYNAMIC RECOMMENDATION PARSER
    // =========================================================================
    size_t profiles_count = sizeof(TAILORED_ATTACKS) / sizeof(TAILORED_ATTACKS[0]);
    for (size_t i = 0; i < profiles_count; i++) {
        // Use strcmp for safe C-string text comparison. Returns 0 if they match perfectly.
        if (strcmp(report.attack_type, TAILORED_ATTACKS[i].attack_type) == 0) {
            report.recommendation = TAILORED_ATTACKS[i].recommendation;
            break; 
        }
    }

    return report;
}