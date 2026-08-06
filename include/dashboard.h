#ifndef DASHBOARD_H
#define DASHBOARD_H

#include <Arduino.h>   // Added to support native String types
#include <WebServer.h>

class Dashboard {
public:
    Dashboard();
    ~Dashboard();
    void init();
    void handleRequests();

    static Dashboard *globalInstance;

private:
    WebServer *server;

    // Methods must be static so static HTTP handlers can execute them
    // Validation Helpers
    static bool validateInput(const String &input, const String &fieldName, int maxLength, bool allowEmpty = false);
    static bool validateNumericInput(const String &input, const String &fieldName, int minValue, int maxValue);
    static bool validateFloatInput(const String &input, const String &fieldName, float minValue, float maxValue);
    static bool validateBooleanInput(const String &input, const String &fieldName);

    // Authentication
    // Returns true if request is authorized. If false, caller must return
    // immediately: a 401 WWW-Authenticate response has already been sent.
    static bool authorizeRequest(bool requireWrite = false);

    // HTTP Endpoint Handlers (Static for WebServer callback compatibility)
    static void handleRoot();
    static void handleData();
    static void handleEvents();
    static void handleCSV();
    static void handleHealth();
    static void handleStressTest();
    static void handleConfig();
    static void handleChannelChangeRequest();
    static void handleNotFound();

    // Virtual File System Routers
    static void handleCSS();
    static void handleJS();
    static void handleChartJS();
    static void handleFavicon();
    static void handleSystem();
};

#endif // DASHBOARD_H