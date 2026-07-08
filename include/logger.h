#ifndef LOGGER_H
#define LOGGER_H

#include <Arduino.h>
#include <SPIFFS.h>
#include <vector>
#include <WebServer.h> // Fixed: Added for streamLogs
#include <freertos/semphr.h>
#include "types.h"
#include "config.h"

class Logger {
public:
    static void init();
    
    // Core Logging
    static void logEvent(const Event& event);
    static void logThreat(float score, const char* classification);
    static void logSystem(const char* message);
    static void logError(const char* component, const char* error);
    
    // Enterprise Logging
    static void log(LogLevel level, LogCategory category, const String& component, const String& message, const String& context = "");
    static void debug(const String& component, const String& message, const String& context = "");
    static void info(const String& component, const String& message, const String& context = "");
    static void warning(const String& component, const String& message, const String& context = "");
    static void error(const String& component, const String& message, const String& context = "");
    static void critical(const String& component, const String& message, const String& context = "");
    
    static void logPerformance(const String& operation, unsigned long duration, const String& metrics = "");
    static void logMemory(const String& operation, size_t before, size_t after);
    static void logSecurity(const String& event, const String& source, const String& details = "");
    static void logStructured(LogLevel level, LogCategory category, const String& component, const String& message, const std::vector<std::pair<String, String>>& fields = {});
    
    // Configuration
    static void setLogLevel(LogLevel minLevel);
    static void setLogRotation(bool enable, int maxEntries = 1000);
    static void setLogFormat(const String& format);
    static void enablePerformanceLogging(bool enable);
    
    // File Management
    static void rotateLogsIfNeeded();
    static bool streamLogs(WebServer& server);
    static bool exportLogs(const char* format);
    static bool exportAsJSON(const String& filename);
    static bool exportAsCSV(const String& filename);
    static int getLogCount();
    static unsigned long getLastRotation();
    static void clearLogs();
    
    // Statistics
    struct LogStats {
        int totalEntries;
        int entriesByLevel[5];
        int entriesByCategory[6];
        unsigned long lastLogTime;
        size_t currentSize;
        int rotationCount;
    };
    static LogStats getStatistics();
    
    // Search & Filtering
    static void search(const String& query, std::vector<LogEntry>& results, LogLevel minLevel = LOG_DEBUG);
    static void getRecentEntries(std::vector<LogEntry>& results, int count = 100);
    static void getEntriesByComponent(const String& component, std::vector<LogEntry>& results, int maxCount = 50);
    static std::vector<String> generateRecommendations(const String& classification);

private:
    static String logFile;
    static int maxLogEntries;
    static int logCount;
    static unsigned long lastRotation;
    static SemaphoreHandle_t logMutex; 
    
    static LogLevel minLogLevel;
    static bool logRotationEnabled;
    static String logFormat;
    static bool performanceLoggingEnabled;
    static LogStats statistics;

    // Internal Helpers
    static LogEntry parseLogLine(const String& line);
    static void appendToJSON(const Event& event);
    static void appendToCSV(const Event& event);
    static void writeToFile(const String& entry);
    static String getCurrentTime();
    static bool shouldRotateLogs();
    static void rotateLogs();
    static String formatLogEntry(const char* classification, const char* recommendation);
    static String formatLogEntry(const LogEntry& entry);
    static void updateStatistics(const LogEntry& entry);
    static bool shouldLog(LogLevel level);
    static String levelToString(LogLevel level);
    static String categoryToString(LogCategory category);
    static void addEntry(const LogEntry& entry);
};

// =============================================================================
// UTILITY MACROS
// =============================================================================
#define LOG_DEBUG_C(component, message) Logger::debug(component, message)
#define LOG_INFO_C(component, message) Logger::info(component, message)
#define LOG_WARNING_C(component, message) Logger::warning(component, message)
#define LOG_ERROR_C(component, message) Logger::error(component, message)
#define LOG_CRITICAL_C(component, message) Logger::critical(component, message)

#define LOG_PERF(operation, duration) Logger::logPerformance(operation, duration)
#define LOG_MEMORY(operation, before, after) Logger::logMemory(operation, before, after)
#define LOG_SECURITY(event, source) Logger::logSecurity(event, source)
#define LOG_SECURITY_C(component, event, source) Logger::logSecurity(event, source, component)

#define PERF_TIMER_START(name) unsigned long perf_start_##name = millis()
#define PERF_TIMER_END(name) \
    do { \
        unsigned long perf_duration = millis() - perf_start_##name; \
        Logger::logPerformance(#name, perf_duration); \
    } while(0)

#endif // LOGGER_H