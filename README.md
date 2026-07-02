# ESP Cyber Sentinel

A lightweight, ESP32-based 802.11 wireless threat detection system with real-time web dashboard.

## Features
- **Wi-Fi Packet Sniffing**: Promiscuous mode monitoring of 2.4GHz channels
- **Heuristic Threat Detection**: Detects deauth floods, association floods, and signal instability
- **Real-Time Dashboard**: Web-based UI served over a standalone access point
- **Multi-Tasking FreeRTOS Design**: Strict core separation for real-time performance
- **Guerilla Sweep (Anchor & Blitz)**: 80/20 channel time-slicing for continuous monitoring + dashboard responsiveness
- **Threat Lock Mode**: Auto-locks to suspicious channels with time-sliced dashboard access
- **Thread-Safe Architecture**: Mutex-protected global state for cross-core communication

## Hardware Requirements
- ESP32 Development Board
- Optional: LED for sniffing indicator (GPIO 2)

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

## Project Structure
```
├── include/          # Header files
├── src/              # Source code
├── data/             # SPIFFS filesystem files (dashboard)
├── platformio.ini    # PlatformIO configuration
└── README.md         # This file
```

## License
MIT License — feel free to use, modify, and distribute.
