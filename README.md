# ESP Cyber Sentinel

A lightweight, ESP32-based 802.11 wireless intrusion detection system (WIDS) with a real-time web dashboard — built for passive Wi-Fi threat monitoring on constrained embedded hardware.

---

## Overview

ESP Cyber Sentinel runs entirely on a single ESP32, using promiscuous-mode packet sniffing and heuristic analysis to detect common wireless attacks — deauthentication floods, association floods, and signal instability — without any external server or cloud dependency. Detection results are served live through a self-hosted dashboard, accessible over the ESP32's own access point.

The system is built around a dual-core FreeRTOS architecture: one core is dedicated entirely to radio monitoring and channel control, while the other handles packet analysis, the web dashboard, and logging — keeping detection responsive even while the UI is in active use.

## Features

- **Wi-Fi Packet Sniffing** — Promiscuous-mode monitoring across all 2.4GHz channels (1–13)
- **Heuristic Threat Detection** — Detects deauth floods, association floods, and signal instability using EMA-smoothed thresholds
- **Real-Time Dashboard** — Self-hosted web UI served directly from the ESP32's access point
- **Dual-Core FreeRTOS Design** — Strict core separation keeps detection and UI responsiveness independent of each other
- **Guerilla Sweep (Anchor & Blitz)** — 80/20 channel time-slicing for continuous monitoring without sacrificing dashboard responsiveness
- **Threat Lock Mode** — Automatically locks onto a suspicious channel while preserving time-sliced dashboard access
- **Thread-Safe State** — Mutex-protected shared state across cores
- **Manual Channel Control** — Override auto-hop and monitor a specific channel on demand
- **Persistent Dashboard Storage** — SPIFFS-backed filesystem for dashboard assets and logs
- **Built-In Stress Test Harness** — One-click synthetic attack injection for demos and threshold tuning (build-gated, disabled by default in release builds)
- **Memory Safety** — Heap monitoring, mutex timeouts, and defensive state handling throughout

## Hardware Requirements

- ESP32 development board (any model, 4MB+ flash, no PSRAM required)
- Optional: status LED on GPIO 2
- Optional: additional LEDs/buttons as defined in `config.h`

## Getting Started

### Build & Flash

Requires [PlatformIO](https://platformio.org/).

```bash
# Build and upload firmware
pio run -e core -t upload

# Upload dashboard filesystem (required — dashboard won't load without this)
pio run -e core -t uploadfs
```

### Access the Dashboard

1. Connect to the access point `CyberSentinel-Fallback` (password: `fallback123456` — **change before deploying**)
2. Navigate to `http://192.168.4.1`
3. Sign in with HTTP Basic Auth (default: `admin` / `cybersentinel` — **change before deploying**)
4. View live threat score, packet counts, and channel status; switch between auto-hop and manual channel modes as needed

---

## ⚠️ Before You Deploy

This is educational/research software, not a production-grade security appliance. Read this section before flashing to anything beyond a bench test.

- **Not a substitute for professional IDS/IPS.** Heuristic detection can produce false positives (e.g. normal roaming, congested channels) and false negatives. Don't rely on it as a sole line of defense.
- **Check local regulations.** Promiscuous-mode Wi-Fi monitoring may be legally restricted depending on your jurisdiction. Only monitor networks you own or have explicit permission to monitor.
- **Passive only.** By default, this operates strictly as a detection system — it does not block, deauth, or otherwise interfere with traffic.

### Pre-Flight Checklist

1. **Change default AP credentials** in `include/config.h` (`AP_SSID`, `AP_PASS`) — shipped defaults are for demo use only
2. **Change dashboard login** in `include/config.h` (`DASH_AUTH_USER`, `DASH_AUTH_PASS`) — AP access + default credentials means trivial takeover
3. **Review detection thresholds** in `include/config.h`:
   - `DEAUTH_THRESHOLD` (default: 2.0 pkt/s) — lower = more sensitive, more false positives
   - `ASSOC_THRESHOLD` (default: 100 pkt/s)
   - `RSSI_VARIANCE_THRESHOLD` (default: 15.0)
4. **Confirm `DEVELOPMENT_MODE` is `0`** for release builds
5. **Flash both firmware and filesystem** — skipping `uploadfs` leaves the dashboard unreachable

---

## Stress Test Harness

A built-in stress test simulates a realistic deauth-flood attack directly inside the detection pipeline — no second device required. Useful for:

- Demoing threat-score escalation and CRITICAL classification live
- Tuning detection thresholds against a known synthetic profile
- Verifying Threat Lock auto-engages correctly at threshold
- Confirming the dashboard stays responsive under simulated peak load

**No radio transmission occurs.** The injector writes synthetic packet metadata directly into the same FreeRTOS queue the real promiscuous-mode receiver feeds — the detection pipeline processes it identically to a real capture, but nothing is broadcast over the air.

### Build Modes

| Environment | Stress Test | Behavior |
|---|---|---|
| `core` (release, default) | Disabled | Dashboard shows a disabled state; injector code is compiled out entirely |
| `internal` | Enabled | Fully interactive toggle in the dashboard |

This is intentionally build-gated: shipping the injector live in a release build would let anyone who obtains your AP credentials trigger a self-inflicted denial-of-service against your own monitoring pipeline.

### Running It

```bash
# Flash the internal build + filesystem
pio run -e internal -t upload
pio run -e internal -t uploadfs
```

Then, from the dashboard, click **Start Stress Test**. Within ~15 seconds you should see:
- Classification escalate: `SAFE → WARNING → RECONNAISSANCE → CRITICAL`
- Threat score climb to ≥ 7.0
- Radio mode switch: `Auto-Hop → Threat Lock`
- Dashboard continuing to update (proving the 20% home-channel time slice holds under load)

Click **Stop Stress Test** to halt injection; the threat score decays back to baseline via the same EMA smoothing used in normal operation.

### Scripted / Headless Use

```bash
# Check status (unauthenticated read)
curl -u admin:cybersentinel http://192.168.4.1/stresstest

# Start
curl -u admin:cybersentinel "http://192.168.4.1/stresstest?state=on"

# Stop
curl -u admin:cybersentinel "http://192.168.4.1/stresstest?state=off"
```

---

## How It Works

### Channel Time-Slicing

| Mode | Behavior |
|---|---|
| Auto-Hop (normal) | 80% on home channel (dashboard), 20% sweeping other channels |
| Threat Lock | 80% on the flagged channel, 20% on home channel |
| Manual | 80% on selected channel, 20% on home channel |

### Detection Heuristics

EMA-smoothed thresholds flag:
- **Deauthentication flood** — >2 disassoc packets/sec
- **Association flood** — >100 assoc packets/sec with high MAC entropy
- **Signal instability** — high RSSI variance

### Core Assignment

- **Core 0** — Radio controller (channel hopping, time-slicing)
- **Core 1** — Packet processing, dashboard, logging, all other tasks

## Project Structure

```
├── include/          # Headers (config, types, etc.)
├── src/              # Source code
├── data/             # SPIFFS dashboard assets
├── platformio.ini    # PlatformIO configuration
└── README.md
```

## Current Limitations

| Capability | Status |
|---|---|
| Deauth flood detection | ✅ Heuristic (rate-based) |
| Association/spoof flood detection | ✅ Heuristic (rate + entropy) |
| Signal instability / jamming | ✅ RSSI variance |
| Rogue AP detection | ❌ Planned (v2) |
| Per-MAC tracking | ❌ Planned (v2) |
| Active mitigation | ❌ Not implemented — detection only, by design |
| Cloud sync / OTA | ❌ Planned (v2) |
| AI/ML classification | ❌ Planned (v3) |
| 5GHz band support | ❌ Hardware limitation (ESP32) |
| Protected Management Frames (PMF) | ⚠️ Advisory-only, no active enforcement |

## Roadmap

- **v2** — Cloud sync, OTA updates, intrusion prevention (active mitigation)
- **v3** — Raspberry Pi Zero 2W multi-node coordinator, AI/ML-based classification

## License

MIT License — free to use, modify, and distribute.