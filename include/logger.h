#ifndef LOGGER_H
#define LOGGER_H

#include <Arduino.h>
#include <SPIFFS.h>
#include <WebServer.h>
#include <freertos/semphr.h>
#include <vector>
#include "types.h"
#include "config.h"

// =============================================================================
// CYBER SENTINEL — LOGGER
// =============================================================================
// Thread-safe SPIFFS logger with CSV-on-write, JSON/CSV export, and
// severity/category filtering. Uses a FreeRTOS mutex to avoid flash corruption
// when the telemetry task and UI task both try to append concurrently.

class Logger {
public:
    // --- Lifecycle ---------------------------------------------------------
    static void init();

    // --- Core (used by the runtime today) ---------------------------------
    static void logEvent(const Event& event);
    static void logThreat(float score, const char* classification);
    static void logSystem(const char* message);
    static void logError(const char* component, const char* error);

    // --- Enterprise (plumbed, ready for use when needed) ------------------
    static void log(LogLevel level, LogCategory category,
                    const String& component, const String& message,
                    const String& context = "");
    static void debug   (const String& c, const String& m, const String& ctx = "");
    static void info    (const String& c, const String& m, const String& ctx = "");
    static void warning (const String& c, const String& m, const String& ctx = "");
    static void error   (const String& c, const String& m, const String& ctx = "");
    static void critical(const String& c, const String& m, const String& ctx = "");

    static void logPerformance(const String& op, unsigned long ms,
                               const String& metrics = "");
    static void logMemory     (const String& op, size_t before, size_t after);
    static void logSecurity   (const String& ev, const String& src,
                               const String& details = "");
    static void logStructured (LogLevel level, LogCategory cat,
                               const String& component, const String& message,
                               const std::vector<std::pair<String, String>>& fields = {});

    // --- Configuration -----------------------------------------------------
    static void setLogLevel               (LogLevel minLevel);
    static void setLogRotation            (bool enable, int maxEntries = MAX_LOG_ENTRIES);
    static void setLogFormat              (const String& format);  // "json" | "csv" | "text"
    static void enablePerformanceLogging  (bool enable);

    // --- File I/O ----------------------------------------------------------
    static void rotateLogsIfNeeded();
    static bool streamLogs   (WebServer& server);
    static bool exportLogs   (const char* format);
    static bool exportAsJSON (const String& filename);
    static bool exportAsCSV  (const String& filename);
    static int  getLogCount  ();
    static unsigned long getLastRotation();
    static void clearLogs();

    // --- Telemetry ---------------------------------------------------------
    struct LogStats {
        int           totalEntries;
        int           entriesByLevel[5];
        int           entriesByCategory[6];
        unsigned long lastLogTime;
        size_t        currentSize;
        int           rotationCount;
    };
    static LogStats getStatistics();

    // --- Querying ----------------------------------------------------------
    static void search               (const String& query,
                                      std::vector<LogEntry>& results,
                                      LogLevel minLevel = LOG_DEBUG);
    static void getRecentEntries     (std::vector<LogEntry>& results,
                                      int count = 100);
    static void getEntriesByComponent(const String& component,
                                      std::vector<LogEntry>& results,
                                      int maxCount = 50);

private:
    static String            logFile;
    static int               maxLogEntries;
    static int               logCount;
    static unsigned long     lastRotation;
    static SemaphoreHandle_t logMutex;

    static LogLevel minLogLevel;
    static bool     logRotationEnabled;
    static String   logFormat;
    static bool     performanceLoggingEnabled;
    static LogStats statistics;

    // Internal helpers
    static LogEntry parseLogLine(const String& line);
    static void     appendToCSV(const Event& event);
    static void     writeToFile (const String& entry);
    static String   getCurrentTime();
    static bool     shouldRotateLogs();
    static void     rotateLogs();
    static String   formatLogEntry(const char* classification, const char* recommendation);
    static String   formatLogEntry(const LogEntry& entry);
    static void     updateStatistics(const LogEntry& entry);
    static bool     shouldLog(LogLevel level);
    static String   levelToString(LogLevel level);
    static String   categoryToString(LogCategory category);
    static void     addEntry(const LogEntry& entry);
};

#endif // LOGGER_H
