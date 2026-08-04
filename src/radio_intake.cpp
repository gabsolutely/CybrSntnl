#include "radio_intake.h"
#include <WiFi.h>
#include "config.h"
#include "feature_extraction.h"
#include <esp_crc.h>
#include <esp_wifi.h> 
#include <esp_wifi_types.h>
#include <esp_rom_crc.h>

// =============================================================================
// GLOBAL INSTANCE REFERENCE FOR CALLBACK
// =============================================================================
RadioIntake* g_radioIntakeInstance = nullptr;

// =============================================================================
// INSTANCE MEMBER INITIALIZATION
// =============================================================================
RadioIntake::RadioIntake() {
    packetQueue = nullptr;
    totalPacketCount = 0;
    lastCapture = 0;
    g_radioIntakeInstance = this;
}

RadioIntake::~RadioIntake() {
    if (g_radioIntakeInstance == this) {
        g_radioIntakeInstance = nullptr;
    }
    if (packetQueue != nullptr) {
        vQueueDelete(packetQueue);
    }
}

// Initialize Radio Intake Subsystem
bool RadioIntake::begin() {
    Serial.println("📡 Initializing Radio Intake Core Components...");
    
    // Create the central FreeRTOS queue
    packetQueue = xQueueCreate(MAX_BUFFER_SIZE, sizeof(Metadata));
    if (packetQueue == nullptr) {
        Serial.println("❌ FATAL: Failed to create central packet queue!");
        return false;
    }
    
    // Register promiscuous callback hook
    esp_wifi_set_promiscuous_rx_cb(&RadioIntake::wifiPromiscuousCallback);
    
    Serial.println("✅ Radio Intake Queue & Hook Registered Successfully.");
    return true;
}

// =============================================================================
// PACKET CAPTURE CALLBACK (ISR Safe, Zero Heap Allocations)
// =============================================================================
void RadioIntake::wifiPromiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_radioIntakeInstance || !g_radioIntakeInstance->packetQueue) return;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    if (!pkt || pkt->rx_ctrl.sig_len == 0) return;
    
    // Enforce minimum standard 802.11 frame header size boundary check
    if (pkt->rx_ctrl.sig_len < 24) return;
    
    // Zero out struct entirely to eliminate memory garbage bugs
    Metadata metadata = {}; 
    
    metadata.ts = millis();
    metadata.rssi = pkt->rx_ctrl.rssi;
    metadata.channel = pkt->rx_ctrl.channel;
    metadata.length = pkt->rx_ctrl.sig_len;
    
    // 802.11 Frame Parsing Bit Extraction Logic
    uint8_t frameControl0 = pkt->payload[0];
    metadata.frame_type = (frameControl0 >> 2) & 0x03; // Extract type bits
    metadata.subtype    = (frameControl0 >> 4) & 0x0F; // Extract subtype bits
    
    // Parse Beacon Interval if it's a valid management beacon frame
    if (metadata.frame_type == 0x00 && metadata.subtype == 0x08 && pkt->rx_ctrl.sig_len >= 38) {
        uint16_t* beacon_int_ptr = (uint16_t*)(pkt->payload + 32);
        metadata.beacon_interval = (float)(*beacon_int_ptr);
    } else {
        metadata.beacon_interval = 0.0f;
    }

    // Extract raw Transmitter MAC Address (Address 2)
    uint8_t* src_mac = pkt->payload + 10; 
    memcpy(metadata.mac, src_mac, 6);
    
    // Pure integer mathematical hashing
    metadata.hashed_src_mac = esp_crc32_le(0, src_mac, 6); 
    metadata.hashed_dst_mac = 0; 
    metadata.ssid[0] = '\0'; 

    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    
    // Push directly to queue without waiting. If full, drop frame gracefully.
    if (xQueueSendFromISR(g_radioIntakeInstance->packetQueue, &metadata, &xHigherPriorityTaskWoken) == pdPASS) {
        g_radioIntakeInstance->totalPacketCount++;
    }

    // Context switch if needed to keep processing snappy
    if (xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
}

// =============================================================================
// DATA ACCESS METHODS
// =============================================================================
Metadata RadioIntake::getNextPacket() {
    Metadata packet = {};
    getNextMetadata(packet);
    return packet;
}

bool RadioIntake::getNextMetadata(Metadata& meta) {
    if (packetQueue == nullptr) return false;
    
    // Non-blocking pop from queue inside normal task thread
    return xQueueReceive(packetQueue, &meta, 0) == pdTRUE;
}

bool RadioIntake::hasPacket() {
    return getBufferSize() > 0;
}

int RadioIntake::getPacketCount() {
    return totalPacketCount;
}

int RadioIntake::getBufferSize() {
    if (packetQueue == nullptr) return 0;
    return uxQueueMessagesWaiting(packetQueue);
}

// =============================================================================
// UTILITY METHODS
// =============================================================================
void RadioIntake::clearBuffer() {
    if (packetQueue != nullptr) {
        xQueueReset(packetQueue);
    }
}

bool RadioIntake::processPackets() {
    int currentWaiting = getBufferSize();
    if (currentWaiting == 0) {
        return false;
    }
    
    static unsigned long lastOutputTime = 0;
    static int packetsSinceLastOutput = 0;
    int processed = 0;
    
    Metadata packet;
    FeatureExtraction* featEngine = FeatureExtraction::getInstance(this);
    
    while (hasPacket() && processed < MAX_PACKETS_PER_CYCLE) {
        if (getNextMetadata(packet)) {
            if (featEngine) {
                featEngine->processMetadata(packet);
            }
            packetsSinceLastOutput++;
            processed++;
        }
    }
    
    unsigned long now = millis();
    if (now - lastOutputTime > RADIO_OUTPUT_INTERVAL_MS && packetsSinceLastOutput > 0) {
        Serial.printf("Processed %d packets (buffer: %d/%d)\n", 
                     packetsSinceLastOutput, getBufferSize(), MAX_BUFFER_SIZE);
        packetsSinceLastOutput = 0;
        lastOutputTime = now;
    }
    
    static unsigned long lastWarningTime = 0;
    if (getBufferSize() > MAX_BUFFER_SIZE * QUEUE_WARNING_THRESHOLD && (now - lastWarningTime > QUEUE_WARNING_INTERVAL_MS)) {
        Serial.printf("Warning: Queue at %d/%d capacity\n", getBufferSize(), MAX_BUFFER_SIZE);
        lastWarningTime = now;
    }
    
    return processed > 0;
}

// =============================================================================
// INJECT / SIMULATE METHODS (For testing & Stress Test Mode)
// =============================================================================
bool RadioIntake::injectMetadata(const Metadata& meta) {
    if (packetQueue == nullptr) return false;

    // Core 1 task execution injection. Timeout 0 ensures we don't hold up 
    // the simulator task if the queue backs up under intense load.
    if (xQueueSend(packetQueue, &meta, 0) == pdPASS) {
        totalPacketCount++;
        return true;
    }
    
    return false; // Queue full
}

void RadioIntake::simulateMetadata(const Metadata& meta) {
    injectMetadata(meta);
}