#ifndef RADIO_INTAKE_H
#define RADIO_INTAKE_H

#include "config.h"         // Core macro constraints (MAX_BUFFER_SIZE)
#include "types.h"          // Structured metadata definitions
#include <esp_wifi_types.h> // Underlying promiscuous packet layouts
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

class RadioIntake {
public:
    RadioIntake();
    ~RadioIntake();
    bool begin();
    
    // Core packet processing interface
    Metadata getNextPacket();
    bool getNextMetadata(Metadata& meta);
    bool hasPacket();
    int getPacketCount();
    int getBufferSize();
    void clearBuffer();
    bool processPackets();
    
    // For testing and simulation purposes
    bool injectMetadata(const Metadata& meta);
    void simulateMetadata(const Metadata& meta);

private:
    static void wifiPromiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    
    // FreeRTOS Thread-safe Queue
    QueueHandle_t packetQueue;
    volatile int totalPacketCount;
    unsigned long lastCapture;
};

#endif // RADIO_INTAKE_H