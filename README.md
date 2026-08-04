# ESP Cyber Sentinel

A lightweight, ESP32-based 802.11 wireless threat detection system with real-time web dashboard.

## Features
- **Wi-Fi Packet Sniffing**: Promiscuous mode monitoring of 2.4GHz channels (1-13)
- **Heuristic Threat Detection**: Detects deauth floods, association floods, and signal instability
- **Real-Time Dashboard**: Web-based UI served over a standalone access point
- **Multi-Tasking FreeRTOS Design**: Strict core separation for real-time performance
- **Guerilla Sweep (Anchor & Blitz)**: 80/20 channel time-slicing for continuous monitoring + dashboard responsiveness
- **Threat Lock Mode**: Auto-locks to suspicious channels with time-sliced dashboard access
- **Thread-Safe Architecture**: Mutex-protected global state for cross-core communication
- **Manual Channel Selection**: Manually choose any channel with auto time-slicing to keep dashboard alive
- **SPIFFS File System**: Persistent logging and dashboard file storage
- **Memory Safety Features**: Heap monitoring, mutex timeouts, and safe state handling

## Hardware Requirements
- ESP32 Development Board (any model with 4MB+ flash, NO PSRAM required)
- Optional: LED for sniffing indicator (GPIO 2)
- Optional: Other LEDs and buttons as defined in `config.h`

## Building & Uploading
1. Install [PlatformIO](https://platformio.org/)
2. Open the project in VS Code or your IDE of choice
3. Build and upload using the `core` environment:
   ```bash
   pio run -e core -t upload
   ```
4. Upload the SPIFFS filesystem (contains dashboard files):
   ```bash
   pio run -e core -t uploadfs
   ```

## Dashboard
1. Connect to the Wi-Fi AP `CyberSentinel-Fallback` (password: `fallback123456`)
2. Open a browser and navigate to `http://192.168.4.1`
3. You'll see the real-time threat score, packet counts, and other metrics
4. Use the channel selector to switch between auto-hop and manual channels

## Project Structure
```
├── include/          # Header files (config, types, etc.)
├── src/              # Source code
├── data/             # SPIFFS filesystem files (dashboard)
├── platformio.ini    # PlatformIO configuration
└── README.md         # This file
```

## Key Concepts
### Channel Time-Slicing
- **Normal (Auto-Hop)**: 80% on HOME_CHANNEL (1) for dashboard, 20% sweeping other channels
- **Threat Lock**: 80% on threat channel, 20% on HOME_CHANNEL for dashboard
- **Manual Channel**: 80% on selected channel, 20% on HOME_CHANNEL for dashboard

### Threat Detection
Uses heuristic-based detection with exponential moving average (EMA) smoothing:
- **Deauthentication Flood**: >2 disassoc packets/sec
- **Association Flood**: >100 assoc packets/sec with high MAC entropy
- **Signal Instability**: High RSSI variance

### Multi-Core Task Assignment
- **Core 0**: Radio Controller (time-slicing and channel hopping)
- **Core 1**: All other tasks (packet processing, dashboard, logging, etc.)

## Configuration
All configuration constants are in `include/config.h`:
- Wi-Fi SSID/password
- GPIO pins
- Channel sweep interval
- Threat thresholds
- Memory limits

## Future Plans
- **V2**: Cloud sync, OTA updates, IPS (Intrusion Prevention System)
- **V3**: RPi Zero 2W coordinator, AI/ML detection, multi-node configuration

## License
MIT License — feel free to use, modify, and distribute.

---

## ⚠️ DISCLAIMER & PRODUCTION NOTES

**THIS IS EDUCATIONAL / RESEARCH SOFTWARE. IT IS NOT A SUBSTITUTE FOR PROFESSIONAL-GRADE SECURITY TOOLS.**

- CyberSentinel is provided "AS IS" with no warranties. Use at your own risk.
- Heuristic detection may produce **false positives** (e.g., normal roaming, congested channels) and **false negatives**. Do not rely on it as your sole IDS/IPS.
- Promiscuous-mode Wi-Fi monitoring may be subject to local laws. Only run this on networks you own or have explicit written permission to monitor.
- In its default configuration, the software operates as a passive WIDS (Wireless Intrusion *Detection* System) only. It performs no active blocking or deauthentication.

### Pre-Flight Checklist (Before You Flash)
1. **Change the default AP credentials** in `include/config.h` (look for `AP_SSID` and `AP_PASS`). The shipped defaults (`CyberSentinel-Fallback` / `fallback123456`) are for demo use only.
2. **Review threat thresholds** in `include/config.h`:
   - `DEAUTH_THRESHOLD` (default: 2.0 pkt/s) – lower = more sensitive, more false positives
   - `ASSOC_THRESHOLD` (default: 100 pkt/s)
   - `RSSI_VARIANCE_THRESHOLD` (default: 15.0)
3. **Confirm `DEVELOPMENT_MODE` is 0** in `include/config.h` (already set for release builds).
4. **Upload both firmware + SPIFFS** using the two PlatformIO commands above. Skipping `uploadfs` leaves you without a dashboard.

### Basic Auth (Enabled by Default)
The dashboard now requires HTTP Basic Authentication to prevent accidental drive-by access from anyone on the AP.

- **Default username:** `admin`
- **Default password:** `cybersentinel`

Change these in `include/config.h` before flashing (`DASH_AUTH_USER` and `DASH_AUTH_PASS`). Use a unique password — AP access + default creds = trivial takeover.

### Limitations of This Build
| Capability | Support |
|---|---|
| Deauth flood detection | ✅ Heuristic (rate-based) |
| Assoc / spoof flood detection | ✅ Heuristic (rate + entropy) |
| Signal instability / jamming | ✅ RSSI variance |
| Rogue AP detection | ❌ Planned V2 |
| Per-MAC tracking | ❌ Planned V2 |
| Active mitigation (deauth frames) | ❌ Not implemented (IDS-only) |
| Cloud sync / OTA | ❌ Planned V2 |
| AI / ML classification | ❌ Planned V3 |
| 5 GHz bands | ❌ ESP32 hardware limitation |
| Protected Mgmt Frames (PMF) | ❌ Advisory-only in recommendations |
