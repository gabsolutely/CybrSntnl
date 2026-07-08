#ifndef THREAT_ANALYZER_H
#define THREAT_ANALYZER_H

#include "types.h"

class ThreatAnalyzer {
public:
    // Converted include guard to match project style guidelines instead of mixing pragma/ifndef definitions
    static ThreatReport analyzeEnvironment(const FeatureVec& features);
};

#endif // THREAT_ANALYZER_H