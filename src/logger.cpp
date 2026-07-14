#include "logger.h"
#include "types.h"
#include "config.h"
#include "globals.h"
#include <Arduino.h>
#include <SPIFFS.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// =============================================================================
// STATIC MEMBER INITIALIZATION
// =============================================================================
SemaphoreHandle_t Logger::logMutex = nullptr;
String Logger::logFile = PATH_EVENTS_CSV;
int Logger::maxLogEntries = MAX_LOG_ENTRIES;
int Logger::logCount = 0;
unsigned long Logger::lastRotation = 0;

LogLevel Logger::minLogLevel = LOG_INFO;
bool Logger::logRotationEnabled = true;
String Logger::logFormat = "json";
bool Logger::performanceLoggingEnabled = true;
Logger::LogStats Logger::statistics = {};

// =============================================================================
// INITIALIZATION METHOD
// =============================================================================
void Logger::init() {
    Serial.println("📝 Logger system initializing...");

    if (!logMutex) {
        logMutex = xSemaphoreCreateMutex();
    }
    
    if (!SPIFFS.begin(true)) {
        Serial.println("❌ SPIFFS not available for logging");
        return;
    }
    
    if (!SPIFFS.exists(logFile)) {
        File file = SPIFFS.open(logFile, "w");
        if (file) {
            file.println("timestamp,classification,notes");
            file.close();
            Serial.println("✅ Created new log file");
        }
    }
    
    lastRotation = millis(); // Initialize tracker state
    Serial.println("✅ Logger initialized successfully");
}

// =============================================================================
// LOGGING METHODS
// =============================================================================
void Logger::logEvent(const Event& event) {
    // Drop directly into our optimized memory-safe handler
    appendToCSV(event);
    
    Serial.printf("📝 LOG: [%lu] Threat: %.2f - Class: %s\n", 
                  event.timestamp, event.threat_score, event.classification ? event.classification : "NONE");
}

void Logger::logThreat(float score, const char* classification) {
    char scoreStr[16];
    dtostrf(score, 4, 2, scoreStr);
    
    String entry = String(getCurrentTime() + ",threat," + scoreStr + "," + 
                   classification + "," + String(currentChannel));
    writeToFile(entry);
    
    Serial.printf("🚨 THREAT: Score=%.2f, Class=%s, Channel=%d\n", 
                  score, classification, currentChannel);
}

void Logger::logSystem(const char* message) {
    String entry = String(getCurrentTime()) + ",system," + message;
    writeToFile(entry);
    
    Serial.printf("🔧 SYS: %s\n", message);
}

void Logger::logError(const char* component, const char* error) {
    String entry = String(getCurrentTime()) + ",error," + component + "," + error;
    writeToFile(entry);
    
    Serial.printf("❌ ERROR: [%s] %s\n", component, error);
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================
String Logger::getCurrentTime() {
    unsigned long now = millis();
    unsigned long seconds = now / 1000;
    unsigned long minutes = seconds / 60;
    unsigned long hours = minutes / 60;
    
    char timeStr[32];
    snprintf(timeStr, sizeof(timeStr), "%02lu:%02lu:%02lu", 
             hours % 24, minutes % 60, seconds % 60);
    return String(timeStr);
}

String Logger::formatLogEntry(const char* classification, const char* recommendation) {
    return String(getCurrentTime()) + "," + classification + "," + recommendation;
}

// =============================================================================
// FILE OPERATIONS
// =============================================================================
void Logger::writeToFile(const String& entry) {
    if (logMutex == nullptr) return;

    if (xSemaphoreTake(logMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        bool fileExists = SPIFFS.exists(logFile);
        
        File file = SPIFFS.open(logFile, "a");
        if (!file) {
            xSemaphoreGive(logMutex);
            return;
        }
        
        if (!fileExists) {
            if (logFormat != "json") {
                file.println("timestamp,classification,notes");
            }
        }
        
        file.println(entry);
        file.close();
        
        logCount++;
        if (shouldRotateLogs()) {
            rotateLogs();
        }
        
        xSemaphoreGive(logMutex);
    } else {
        Serial.println("⚠️ Logger Timeout: Dropped entry due to flash congestion");
    }
}

bool Logger::shouldRotateLogs() {
    return logCount >= maxLogEntries || 
           (millis() - lastRotation) > (LOG_ROTATE_DAYS * 24 * 60 * 60 * 1000UL);
}

void Logger::rotateLogsIfNeeded() {
    if (logRotationEnabled && shouldRotateLogs()) {
        rotateLogs();
    }
}

void Logger::rotateLogs() {
    Serial.println("🔄 Rotating logs...");
    String backupFile = String(logFile) + "." + String(millis());
    
    if (SPIFFS.exists(logFile)) {
        SPIFFS.rename(logFile, backupFile);
    }
    
    logCount = 0;
    lastRotation = millis();
    Serial.printf("✅ Log rotated to: %s\n", backupFile.c_str());
}

// =============================================================================
// UTILITY METHODS
// =============================================================================
bool Logger::exportLogs(const char* format) {
    if (!SPIFFS.exists(logFile)) {
        Serial.println("❌ No log file found");
        return false;
    }
    
    String exportFile = String(logFile) + ".export." + String(format);
    
    if (strcmp(format, "json") == 0) {
        return exportAsJSON(exportFile);
    } else if (strcmp(format, "csv") == 0) {
        return exportAsCSV(exportFile);
    } else {
        Serial.println("Unsupported export format");
        return false;
    }
}

bool Logger::exportAsJSON(const String& filename) {
    File source = SPIFFS.open(logFile, "r");
    File dest = SPIFFS.open(filename, "w");
    
    if (!source || !dest) {
        if (source) source.close();
        if (dest) dest.close();
        return false;
    }
    
    dest.println("[");
    bool first = true;
    
    while (source.available()) {
        String line = source.readStringUntil('\n');
        line.trim();
        
        if (line.length() > 0) {
            if (!first) dest.println(",");
            
            dest.println("  {");
            dest.println("    \"raw\": \"" + line + "\"");
            dest.println("  }");
            first = false;
        }
    }
    
    dest.println("]");
    source.close();
    dest.close();
    return true;
}

bool Logger::exportAsCSV(const String& filename) {
    if (logMutex == nullptr) return false;
    
    if (xSemaphoreTake(logMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        File source = SPIFFS.open(logFile, "r");
        File dest = SPIFFS.open(filename, "w");
        
        if (!source || !dest) {
            if (source) source.close();
            if (dest) dest.close();
            xSemaphoreGive(logMutex);
            return false;
        }
        
        uint8_t buffer[128];
        while (source.available()) {
            size_t bytesRead = source.read(buffer, sizeof(buffer));
            dest.write(buffer, bytesRead);
        }
        
        source.close();
        dest.close();
        xSemaphoreGive(logMutex);
        return true;
    }
    return false;
}

int Logger::getLogCount() { return logCount; }
unsigned long Logger::getLastRotation() { return lastRotation; }

void Logger::clearLogs() {
    if (SPIFFS.exists(logFile)) {
        SPIFFS.remove(logFile);
    }
    logCount = 0;
    lastRotation = millis();
}

// =============================================================================
// LOGGING METHODS - ENTERPRISE FEATURES
// =============================================================================
void Logger::log(LogLevel level, LogCategory category, const String& component, 
                 const String& message, const String& context) {
    if (!shouldLog(level)) return;
    
    LogEntry entry;
    entry.timestamp = millis();
    entry.level = level;
    entry.category = category;
    entry.component = component;
    entry.message = message;
    entry.context = context;
    entry.memoryUsage = ESP.getFreeHeap();
    
    addEntry(entry);
    updateStatistics(entry);
}

void Logger::debug(const String& component, const String& message, const String& context) {
    log(LOG_DEBUG, CAT_SYSTEM, component, message, context);
}
void Logger::info(const String& component, const String& message, const String& context) {
    log(LOG_INFO, CAT_SYSTEM, component, message, context);
}
void Logger::warning(const String& component, const String& message, const String& context) {
    log(LOG_WARNING, CAT_SYSTEM, component, message, context);
}
void Logger::error(const String& component, const String& message, const String& context) {
    log(LOG_ERROR, CAT_SYSTEM, component, message, context);
}
void Logger::critical(const String& component, const String& message, const String& context) {
    log(LOG_CRITICAL, CAT_SYSTEM, component, message, context);
}

void Logger::logPerformance(const String& operation, unsigned long duration, const String& metrics) {
    if (!performanceLoggingEnabled) return;
    
    LogEntry entry;
    entry.timestamp = millis();
    entry.level = LOG_INFO;
    entry.category = CAT_PERFORMANCE;
    entry.component = "Performance";
    entry.message = operation + " completed in " + String(duration) + "ms";
    entry.context = metrics;
    entry.memoryUsage = ESP.getFreeHeap();
    
    addEntry(entry);
    updateStatistics(entry);
}

void Logger::logMemory(const String& operation, size_t before, size_t after) {
    LogEntry entry;
    entry.timestamp = millis();
    entry.level = LOG_INFO;
    entry.category = CAT_MEMORY;
    entry.component = "Memory";
    entry.message = operation + " memory change: " + String(before - after) + " bytes";
    entry.context = "Before: " + String(before) + ", After: " + String(after);
    entry.memoryUsage = ESP.getFreeHeap();
    
    addEntry(entry);
    updateStatistics(entry);
}

void Logger::logSecurity(const String& event, const String& source, const String& details) {
    LogEntry entry;
    entry.timestamp = millis();
    entry.level = LOG_WARNING;
    entry.category = CAT_SECURITY;
    entry.component = "Security";
    entry.message = event + " from " + source;
    entry.context = details;
    entry.memoryUsage = ESP.getFreeHeap();
    
    addEntry(entry);
    updateStatistics(entry);
}

void Logger::logStructured(LogLevel level, LogCategory category, const String& component, const String& message, const std::vector<std::pair<String, String>>& fields) {
    LogEntry entry;
    entry.timestamp = millis();
    entry.level = level;
    entry.category = category;
    entry.component = component;
    entry.message = message;
    entry.memoryUsage = ESP.getFreeHeap();
    
    String context = "";
    for (const auto& field : fields) {
        if (!context.isEmpty()) context += ", ";
        context += field.first + "=" + field.second;
    }
    entry.context = context;
    
    addEntry(entry);
    updateStatistics(entry);
}

// =============================================================================
// CONFIGURATION METHODS
// =============================================================================
void Logger::setLogLevel(LogLevel minLevel) { minLogLevel = minLevel; }
void Logger::setLogRotation(bool enable, int maxEntries) { logRotationEnabled = enable; maxLogEntries = maxEntries; }
void Logger::setLogFormat(const String& format) { logFormat = format; }
void Logger::enablePerformanceLogging(bool enable) { performanceLoggingEnabled = enable; }

// =============================================================================
// STATISTICS AND MONITORING
// =============================================================================
Logger::LogStats Logger::getStatistics() { return statistics; }

// =============================================================================
// SEARCH AND FILTERING
// =============================================================================
void Logger::search(const String& query, std::vector<LogEntry>& results, LogLevel minLevel) {
    results.clear();
    if (logMutex && xSemaphoreTake(logMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        File file = SPIFFS.open(logFile, "r");
        if (file) {
            while (file.available()) {
                String line = file.readStringUntil('\n');
                if (line.indexOf(query) != -1) {
                    LogEntry entry = parseLogLine(line);
                    if (entry.level >= minLevel) results.push_back(entry);
                }
            }
            file.close();
        }
        xSemaphoreGive(logMutex);
    } else {
        Serial.println("⚠️ Logger search: Mutex timeout, flash busy");
    }
}

void Logger::getRecentEntries(std::vector<LogEntry>& results, int count) {
    results.clear();
    std::vector<String> lines;
    
    if (logMutex && xSemaphoreTake(logMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        File file = SPIFFS.open(logFile, "r");
        if (file) {
            while (file.available()) {
                lines.push_back(file.readStringUntil('\n'));
            }
            file.close();
        }
        xSemaphoreGive(logMutex);
    } else {
        Serial.println("⚠️ Logger getRecent: Mutex timeout, flash busy");
        return;
    }
    
    int start = (lines.size() > (size_t)count) ? lines.size() - count : 0;
    for (size_t i = start; i < lines.size(); i++) {
        results.push_back(parseLogLine(lines[i]));
    }
}

void Logger::getEntriesByComponent(const String& component, std::vector<LogEntry>& results, int maxCount) {
    results.clear();
    if (logMutex && xSemaphoreTake(logMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        File file = SPIFFS.open(logFile, "r");
        if (file) {
            while (file.available() && (int)results.size() < maxCount) {
                String line = file.readStringUntil('\n');
                LogEntry entry = parseLogLine(line);
                if (entry.component == component) results.push_back(entry);
            }
            file.close();
        }
        xSemaphoreGive(logMutex);
    } else {
        Serial.println("⚠️ Logger getComponent: Mutex timeout, flash busy");
    }
}

// =============================================================================
// PARSING METHODS
// =============================================================================
LogEntry Logger::parseLogLine(const String& line) {
    LogEntry entry;
    int start = 0;
    String parts[7];
    
    for (int i = 0; i < 7; i++) {
        int comma = line.indexOf(',', start);
        if (comma == -1) {
            parts[i] = line.substring(start);
            break;
        }
        parts[i] = line.substring(start, comma);
        start = comma + 1;
    }
    
    entry.timestamp = parts[0].toInt();
    if (parts[1].toInt() > 0 || parts[1] == "0") { 
        entry.level = (LogLevel)parts[1].toInt();
        entry.category = (LogCategory)parts[2].toInt();
        entry.component = parts[3];
        entry.message = parts[4];
        entry.memoryUsage = parts[5].toInt();
        entry.context = parts[6];
    } else {
        entry.message = parts[1];
        entry.context = parts[2];
    }
    return entry;
}

// =============================================================================
// ENHANCED INTERNAL METHODS
// =============================================================================
void Logger::addEntry(const LogEntry& entry) {
    String formatted = formatLogEntry(entry);
    writeToFile(formatted);
}

void Logger::updateStatistics(const LogEntry& entry) {
    statistics.totalEntries++;
    statistics.entriesByLevel[entry.level]++;
    statistics.entriesByCategory[entry.category]++;
    statistics.lastLogTime = entry.timestamp;
    String formatted = formatLogEntry(entry);
    statistics.currentSize += formatted.length();
}

bool Logger::shouldLog(LogLevel level) { return level >= minLogLevel; }

String Logger::levelToString(LogLevel level) {
    const char* levels[] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"};
    return levels[level];
}

String Logger::categoryToString(LogCategory category) {
    const char* categories[] = {"SYSTEM", "SECURITY", "PERFORMANCE", "NETWORK", "MEMORY", "APPLICATION"};
    return categories[category];
}

String Logger::formatLogEntry(const LogEntry& entry) {
    String result = "";
    if (logFormat == "json") {
        result = "{\"timestamp\":" + String(entry.timestamp) + 
                ",\"level\":\"" + levelToString(entry.level) + "\"" +
                ",\"category\":\"" + categoryToString(entry.category) + "\"" +
                ",\"component\":\"" + entry.component + "\"" +
                ",\"message\":\"" + entry.message + "\"" +
                ",\"memory\":" + String(entry.memoryUsage);
        if (!entry.context.isEmpty()) {
            result += ",\"context\":\"" + entry.context + "\"";
        }
        result += "}";
    } else if (logFormat == "csv") {
        result = String(entry.timestamp) + "," +
                levelToString(entry.level) + "," +
                categoryToString(entry.category) + "," +
                entry.component + "," +
                entry.message + "," +
                String(entry.memoryUsage) + "," +
                entry.context;
    } else {
        result = "[" + String(entry.timestamp) + "] " +
                levelToString(entry.level) + " " +
                categoryToString(entry.category) + " " +
                entry.component + ": " + entry.message;
        if (!entry.context.isEmpty()) {
            result += " (" + entry.context + ")";
        }
        result += " [Mem: " + String(entry.memoryUsage) + "]";
    }
    return result;
}

bool Logger::streamLogs(WebServer& server) {
    if (!logMutex) return false;

    if (xSemaphoreTake(logMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        if (!SPIFFS.exists(logFile)) {
            server.send(200, "text/csv", "timestamp,classification,notes\n");
            xSemaphoreGive(logMutex);
            return true;
        }

        File file = SPIFFS.open(logFile, "r");
        if (!file) {
            xSemaphoreGive(logMutex);
            return false;
        }

        server.streamFile(file, "text/csv");
        file.close();
        
        xSemaphoreGive(logMutex);
        return true;
    }
    
    server.send(503, "text/plain", "Error 503: Logger filesystem busy.");
    return false;
}

void Logger::appendToCSV(const Event& event) {
    if (!logMutex || xSemaphoreTake(logMutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        Serial.println("⚠️ Logger: Mutex timeout, dropped event to save core loop");
        return;
    }

    File file = SPIFFS.open(logFile, "a");
    if (!file) {
        Serial.println("⚠️ Logger: Failed to open log file for appending");
        xSemaphoreGive(logMutex);
        return;
    }

    char buffer[256];
    
    // Explicitly cast trace_id to unsigned long so compiler architectures handle %lu safely
    snprintf(buffer, sizeof(buffer), "%lu,%lu,%s,%.2f,%s,%s,%s,%s,%s\n",
         event.timestamp,
         (unsigned long)event.trace_id, 
         event.event_type ? event.event_type : "UNKNOWN",
         event.threat_score,
         event.classification ? event.classification : "NONE",
         event.pre_state ? event.pre_state : "N/A",
         event.post_state ? event.post_state : "N/A",
         event.recommendation ? event.recommendation : "NONE", // Added
         event.notes[0] != '\0' ? event.notes : "No notes");

    file.print(buffer);
    file.close();
    
    logCount++;
    if (shouldRotateLogs()) {
        rotateLogs();
    }
    
    xSemaphoreGive(logMutex);
}

void Logger::appendToJSON(const Event& event) {}

// Fixed: Added implementation to satisfy linker definition rules
std::vector<String> Logger::generateRecommendations(const String& classification) {
    std::vector<String> recs;
    if (classification.indexOf("Deauth") != -1) {
        recs.push_back("Enable 802.11w Management Frame Protection");
        recs.push_back("Switch to a less congested channel");
    } else if (classification.indexOf("Beacon") != -1) {
        recs.push_back("Ignore excessive SSIDs in network manager");
    } else {
        recs.push_back("Continue passive network observability");
    }
    return recs;
}