# 🛡️ Project CyberSentinel Overview

**Edge-Native Wi-Fi Observability & Intrusion Detection System (IDS)**

CyberSentinel is a highly optimized, strictly engineered Wi-Fi telemetry and threat-monitoring engine built entirely on the ESP32 architecture. Operating completely in **promiscuous mode**, it silently intercepts, processes, and analyzes raw 802.11 frame metadata out of the air—all while concurrently serving a real-time, schema-validated web dashboard without a single heap crash or thread collision.

There are no heavy desktop clients. No cloud processing. No vendor lock-in. Just pure, thread-safe C++ firmware squeezing enterprise-grade telemetry out of a $4 microchip.

## 📡 Core Capabilities

* **Ghost-Mode Packet Sniffing:** Operates entirely out-of-band in promiscuous mode. CyberSentinel does not connect to a target network; it listens to the raw electromagnetic spectrum, rendering it nearly invisible to network administrators and attackers.
* **Real-Time Client Dashboard:** Serves a dynamic, responsive HTML/JS UI directly from the ESP32. Visualizes threat scores, MAC entropy, RSSI baselines, and packet velocity in real-time.
* **Spectrum Auto-Hopping & Threat Lock:** Actively scans across 2.4GHz channels (Ch 1, 6, 11) to monitor the entire airspace, with the ability to lock onto specific channels when threat signatures are detected.
* **Data Export Pipeline:** Supports direct exporting of telemetry sessions into JSON, CSV, or formatted Incident Reports for downstream machine learning analysis or research documentation.

## 🏗️ Architecture & Engineering Decisions

CyberSentinel was over-engineered on purpose. The core philosophy was to build a system that relies on strict separation of concerns, hardware-level optimization, and mathematical stability.

* **FreeRTOS ISR Ring Buffers:** Instead of blocking the main loop during heavy Wi-Fi traffic bursts (e.g., deauthentication floods), the system offloads packet capture to an Interrupt Service Routine (ISR) ring buffer. The CPU chews through the queue asynchronously, ensuring minimized packet loss during high-volume bursts through asynchronous buffering and absolute stability under load.
* **Thread-Safe State Management:** The web server and the packet sniffer run on parallel tracks. To prevent race conditions or corrupted JSON payloads, all shared telemetry states are guarded by FreeRTOS Mutexes (`xSemaphoreTake`), ensuring the UI only ever receives pristine, fully assembled data frames.
* **Mathematical Smoothing (EMA):** Instantaneous hardware readings can be erratic. CyberSentinel employs an Exponential Moving Average (EMA) algorithm on the backend to smooth Threat Scores and MAC Entropy. This prevents UI jitter and provides a professional, highly readable trendline of network anomalies.
* **Decoupled Validation Pipeline:** The ESP32 backend is strictly a data provider. The frontend JavaScript acts as a rigid schema validator, ensuring that corrupted or malformed payloads never reach the DOM. This keeps the browser memory footprint light and completely eliminates rendering crashes.

## 🚀 Progress & Milestones

This MVP is the result of relentless iteration. What started as theoretical concepts and basic hardware tests went through a crucible of broken compiles, corrupted logic loops, and memory leaks.

* **Phase 1 (Exploration):** Initial feasibility testing of ESP32 promiscuous mode and basic packet parsing.
* **Phase 2 (The Refactor):** Gutting the initial spaghetti code to implement strict FreeRTOS architecture, introducing ISR queues, and decoupling the web server from the scanning logic.
* **Phase 3 (Current MVP):** Complete synchronization between the hardware sniffer and the web UI. Successful implementation of dynamic color-mapping, EMA mathematical smoothing, and zero-latency data fetching.

The setbacks were the tax paid to build a resilient, hardened architecture. The current build is stable, highly optimized, and ready for active threat-simulation testing.
