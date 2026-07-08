#ifndef FEATURE_EXTRACTION_H
#define FEATURE_EXTRACTION_H

#include <vector>
#include <deque>
#include "types.h"
#include "radio_intake.h"

class FeatureExtraction {
private:
    RadioIntake* radioIntake;
    unsigned long lastExtraction;
    FeatureVec baseline;
    static FeatureExtraction* instance;

    // Sliding window for feature extraction
    int windowSize; 
    std::deque<Metadata> packetWindow;

    // Constructor declaration
    FeatureExtraction(RadioIntake* radio);

public:
    // Singleton pattern for global access
    static FeatureExtraction* getInstance(RadioIntake* radio);
    bool initialize();
    void processMetadata(const Metadata& meta);
    FeatureVec extractFeatures();
    void computeFeatures(FeatureVec& vec);
    void updateBaseline(const FeatureVec& vec);

    // Mathematical helper declarations
    float calculateAvgRSSI();
    float calculateRSSIStd();
    float calculatePacketRate(unsigned long now);
    float calculateMACEntropy();
    float calculateChannelDiversity();
    float calculateTimeVariance();
};

#endif // FEATURE_EXTRACTION_H