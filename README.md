# 🛡️ CyberSentinel Core

> **Open-source $5 ESP32 802.11 management-frame anomaly sensor.**
>
> Passively detects deauth floods, spoofed-assoc floods, and jam/RSSI instability on 2.4GHz — no server, no cloud, no extra hardware.
> Built-in self-validation harness with 4 realistic attacker cadences so you can **prove** detection works on-site in 15 seconds.
>
> *Not a replacement for Suricata/Zeek. The complement your racked NIDS needs for the specific Wi-Fi management attacks it misses.*

---

> **⚠️ HONEST SCOPE BOX** — read this before comparing to a commercial WIDS:
>
> | What this **IS** | What this **IS NOT** |
> |---|---|
> | 802.11 *management*-plane anomaly sensor (deauth, disassoc, assoc-flood, RSSI jam) | Full NIDS / DPI engine — no TCP/IP layer inspection, no port-scan detection, no TLS fingerprinting |
> | $5, battery-sized, zero-infrastructure edge sensor | $1.5k commercial WIDS (Cisco CleanAir / MetaGeek / AirMagnet) — those are 3-radio, 5GHz, PCAP-capable, $$$ |
> | Single-radio channel-time-sliced (80% home / 20% blitz) — designed for *detection + alarm*, not forensics | Forensic-grade packet capture (we can't write PCAP on 4MB SPIFFS; we miss frames during the 20% blitz by design) |
> | 2.4GHz only (ESP32 hardware limitation) | 5GHz / 6GHz capable |
> | MIT-licensed, fully auditable source on GitHub | Black-box appliance with support contract |
>
> If you want a full L3+ NIDS, run Suricata on a RPi. If you want something you tape to a coffee-shop ceiling for $5 and catches script-kiddie deauth attacks your racked NIDS ignores, this is for you.

---

## Philosophy: You Don't Need an Electron App for This

> *"Hello everyone! I made an Intrusion Detection System inside a single ESP32."*

Lately I've been watching a flood of incredible tracing and observability tools land for embedded systems — and they're amazing. But a pattern kept bothering me: massive desktop applications that eat gigabytes of RAM, require dedicated GPUs, and depend on heavy operating systems just to parse network traffic and RTOS telemetry. They are fantastic tools, don't get me wrong — but they sometimes rely on brute force.

**CyberSentinel (CybrSntnl) takes the exact opposite approach.**

I built this project on one belief: if your architecture is clean and efficient enough, you don't need an Electron app or a multi-core processor to achieve real-time, high-quality observability. I crammed a complete 802.11 Intrusion Detection System, a self-hosted web server, a hardware-interrupt packet queue, and a thread-safe data pipeline — all of it — into a few hundred kilobytes of RAM on one $5 ESP32.

### How it works

- **Strict 80/20 resource budget** — the radio interface is pinned to Core 0 and locks 80% of runtime onto raw promiscuous sniffing, leaving exactly 20% for background dashboard updates. The core detection engine is never choked by HTTP traffic.
- **ISR-direct ring buffer** — frame ingestion happens inside the Wi-Fi packet-capture interrupt itself, using an async FreeRTOS ring buffer as the first touchpoint. This is the single biggest reason we don't drop frames during high-velocity floods.
- **Mutex-guarded parallel tasks** — every cross-core state read goes through `xSemaphoreTake` with bounded timeouts, eliminating races. Crucially, the backend serves only raw numbers. It never assembles HTML, formats dates, or builds charts. All heavy string compilation and UI work is offloaded to client-side JavaScript — protecting the precious heap on the device.

### Why this matters (the actual security value)

Modern 802.11 threats don't just knock you offline anymore.

Attackers don't blast flat 10,000 pkt/s deauths like it's 2013. Instead they rely on **micro-bursts**: 1.2 seconds of deauths, 4 seconds of silence, repeat. That cadence is tuned specifically to:

1. force a client to re-authenticate (giving them a PMKID/handshake), and
2. look like a minor network glitch to a human.

Your laptop reconnects in 3 seconds and shows "connected." Your phone never even shows a toast. But your headless IoT assets — security cameras, POS terminals, environmental sensors, doorbells — drop completely and silently, sometimes for minutes, because their firmware has no retry logic.

Your operating system only tells you *after* you've disconnected.

**CyberSentinel acts as airborne radar.** It sits on the wire — sorry, on the air — and exposes the physical-layer exploits happening live right under its nose. The micro-bursts, the spoofed-MAC churn, the RSSI anomalies… the stuff your OS deliberately hides from you so you don't get annoyed.

It looks simple. It looks unperformative. That's the point.

---

## Overview

CyberSentinel Core runs entirely on one $5 ESP32. It uses promiscuous-mode management-frame capture + EMA-smoothed heuristics to flag:

- **Deauthentication / disassociation floods** (script-kid `aireplay-ng -0 0`, Pwnagotchi, wifiphisher)
- **Spoofed-association floods** (high MAC entropy + high assoc rate = classic evil-PT / handshake grabber setup phase)
- **RSSI instability / jamming signatures** (high RSSI variance pattern without channel congestion)

The dual-core FreeRTOS layout keeps the radio responsive *even while you're using the dashboard*:
- **Core 0** → radio controller (Guerilla Sweep 80/20 channel time-slicing, Threat Lock auto-engage)
- **Core 1** → feature extraction, threat scoring, web dashboard, logging

All detection state is mutex-protected across cores with bounded timeouts so a slow dashboard poll can never deadlock the radio pipeline.

The secret sauce vs literally every other ESP32 Wi-Fi "IDS" on GitHub: **the built-in stress harness injects realistic attacker timing profiles into the same queue the real ISR feeds.** This means you can click one button on-site, watch it escalate SAFE → WARNING → RECON → CRITICAL in ~15 seconds, and prove to a client it's calibrated for *their* RF environment before you leave.

## Features

- **802.11 Management-Plane Heuristic Detection** — EMA-smoothed rate + entropy + RSSI-variance detectors
- **4 Attack-Cadence Self-Test Profiles** — CONSTANT / BURSTY / **MICROBURST (handshake-grabber replica)** / MIXED_FRAME_TYPES — injected directly into the pipeline for on-site validation
- **Runtime Tuning Knobs** (dashboard UI or `/stresstest` API) — pkt rate, profile selector, frame-type bitmask, RSSI range, MAC entropy toggle, burst/μburst timing, channel spread, loop cadence
- **3 Dashboard Presets** — 🎯 Handshake Grabber / ☕ Noisy Coffee Shop / 🏫 Classroom Safe (one-click baseline bootstrap)
- **Real-Time Dashboard Over Standalone AP** — threat score, classification LED, entropy + threat charts, ISR queue health, heap monitor
- **Guerilla Sweep (Anchor & Blitz)** — 80% dwell on home channel (keeps dashboard responsive) / 20% 30ms-per-channel blitz (still sees attacks on other channels)
- **Threat Lock Mode** — auto-engages ≥7.0 threat score; 80% dwell on offending channel, 20% home-channel UI slice
- **Manual Channel Override** — drop out of auto-hop and camp on a specific channel from the UI
- **Dual-Core FreeRTOS Pipeline** — strict core pinning (radio on Core 0, UI/analytics on Core 1) prevents cross-domain starvation
- **Thread-Safe Everything** — every cross-core shared read is mutex-gated with bounded timeouts; never deadlock on a slow HTTP response
- **SPIFFS Dashboard + Rotating Logs** — 7-day CSV log rotation, full HTML/CSS/JS dashboard assets on filesystem
- **HTTP Basic Auth Gate** — all write endpoints and telemetry reads are auth-protected; `/health` stays open for monitoring pings
- **Memory Safety Guardrails** — heap low-water / critical thresholds, queue-load 80% health penalty, mutex timeouts everywhere
- **PlatformIO Dual-Env Builds** — `core` (stress-sim compiled out for release) / `internal` (full stress harness + all knobs)

## Hardware Requirements

- ESP32 dev board (any ESP32-WROOM or ESP32-WROVER module; 4MB flash minimum; PSRAM optional)
- **Micro-USB cable** — that's it. No hat, no antenna upgrade, no extra parts for base functionality.
- Optional extras defined in `include/config.h` → wire as needed:
  - Status LED on GPIO 2 (ships enabled — onboard LED on most devkits)
  - RGB threat LED: PIN_LED_RED=17, PIN_LED_GREEN=13, PIN_LED_BLUE=14
  - Override pushbutton: PIN_BUTTON=15
  - Buzzer: PIN_BUZZER=16
  - SSD1306 128×64 I²C OLED: PIN_OLED_SDA=21, PIN_OLED_SCL=22

## Getting Started

### Build & Flash

Requires [PlatformIO](https://platformio.org/):

```bash
# 1. Clone repo
git clone https://github.com/<your-handle>/CyberSentinel-Core.git
cd CyberSentinel-Core/CybrSntnl

# 2. Build with stress tuner enabled (internal env) + flash
pio run -e internal -t upload

# 3. Upload dashboard filesystem (REQUIRED — dashboard is on SPIFFS, not in firmware)
pio run -e internal -t uploadfs
```

Want release build without the stress injector (in case you deploy to a place where someone might abuse it)? Use `-e core` instead of `-e internal` — injector is compiled out, and the dashboard Stress Test panel goes read-only with a banner pointing to rebuild instructions.

### Access the Dashboard

1. Connect to Wi-Fi **`CyberSentinel-Fallback`** / password **`fallback123456`** — ⚠️ **change these in `config.h` BEFORE deploying anywhere semi-public**
2. Navigate to **`http://192.168.4.1`**
3. HTTP Basic Auth: **`admin` / `cybersentinel`** — ⚠️ **change these too** (same `config.h`, Section 5)
4. First-run ritual: Stress Test → 🎯 Handshake Grabber preset → **Start** → watch it hit CRITICAL. If it doesn't hit CRITICAL within 20s, your `DEAUTH_THRESHOLD` is already too high for this venue — lower by 2, retry.

---

## ⚠️ Before You Deploy

This is a deliberately-scoped edge sensor, not a production security appliance. Ship it with your eyes open:

- **Not a substitute for a real L3+ IDS/IPS.** Heuristics on ESP32-class hardware *will* false-positive in RF-dense venues (conferences, LAN parties, dorms). Use this as an alarm, not forensic evidence.
- **Per-venue tuning is NOT optional.** The `config.h` Section 3 defaults are for a quiet residential bedroom at 2am. See the Stress Test section below for the per-venue threshold table.
- **Single-radio blind spot.** The 20% Guerilla Sweep blitz means we *intentionally* miss frames on non-home channels for ~360 ms every 3 seconds. If a 5-second deauth burst happens *exactly* during 3 consecutive blitz windows, you miss it. Good enough for alarm; not good enough for forensics.
- **2.4GHz only.** ESP32 hardware limitation. 5GHz / 6GHz attacks (which most enterprise networks live on) are invisible.
- **Check local regulations.** Promiscuous-mode capture legality varies wildly by jurisdiction. Only monitor airspace you own or have written permission to monitor.
- **Passive only. Always.** CyberSentinel never transmits. It does not deauth, it does not block, it does not spoof. This is by design — you do not want a $5 taped-to-ceiling device with active mitigation privileges.

### Pre-Flight Checklist

1. ⚠️ **Change default AP credentials** → [config.h Section 5](file:///C:/Users/user/Documents/Code%20thingies/CybrSntnl-deploy/CybrSntnl/include/config.h#L119-L133): `AP_SSID`, `AP_PASS`
2. ⚠️ **Change dashboard login** → same section: `DASH_AUTH_USER`, `DASH_AUTH_PASS`
3. **Run 15-minute venue calibration** → see Stress Test section below, use ☕ Coffee Shop preset as baseline, adjust `DEAUTH_THRESHOLD` / `ASSOC_THRESHOLD` / `RSSI_VARIANCE_THRESHOLD` until noisy-normal = SAFE and Handshake Grabber = CRITICAL
4. **Confirm `DEVELOPMENT_MODE 0`** in [config.h](file:///C:/Users/user/Documents/Code%20thingies/CybrSntnl-deploy/CybrSntnl/include/config.h#L21) for release builds (kills debug log spam)
5. **Flash firmware *and* filesystem.** Skipping `uploadfs` = blank dashboard.

---

## Stress Test Harness

A fully-tunable synthetic attack injector lives directly inside the detection pipeline — no second device, no radio transmission. The injector writes fake `Metadata` structs into the same FreeRTOS queue the promiscuous ISR feeds, so the feature extractor, threat analyzer, and Threat Lock all react exactly as they would to a real capture.

### ⚠️ Heavy Per-Environment Tuning Required

Detection thresholds in `config.h` Section 3 are lab defaults for a quiet residential room. They **will false-positive** in RF-dense venues:

| Threshold | Quiet Home | Coffee Shop | Conference / LAN Party |
|---|---|---|---|
| `DEAUTH_THRESHOLD`  (pkt/s) | 2.0 | 10–30 | 20–80 |
| `ASSOC_THRESHOLD`   (pkt/s) | 100 | 300–600 | 800–2000 |
| `RSSI_VARIANCE_THRESHOLD`   | 15.0 | 20–30 | 30–50 |
| `HIGH_THREAT_THRESHOLD`     | 7.0 | 7.5–8.0 | 8.0–8.5 |

Use the Stress Test presets (or craft your own profile + rate) **before** trusting the alarm in a new location. For portfolio demos the recommended preset is **MICROBURST DEAUTH @ 120 pkt/s** — it is the closest replica of a real handshake-grabber behaviour.

### Build Modes

| Environment | `ENABLE_STRESS_SIM` | Behavior |
|---|---|---|
| `core` (release, default) | 0 | Injector compiled out; dashboard panel is read-only and shows a "reflash internal" banner |
| `internal` | 1 | All knobs live — dashboard UI, `/stresstest` query params, `/data` JSON export |

This is intentionally build-gated. Shipping the injector in a release would let anyone with AP credentials run a self-inflicted DoS against your own monitoring pipeline.

### Quick Start

```bash
pio run -e internal -t upload
pio run -e internal -t uploadfs
```

Dashboard → Stress Test panel. Use the three preset buttons to bootstrap, then tune rate/profile/frames with the grid below, then **Start Stress Test**.

### Attack Profiles

| Profile # | Name | Behaviour | Real-world analogue |
|---|---|---|---|
| 0 | `CONSTANT_STREAM` | Flat line, fixed pkt/s | Static jammer, broken driver looping deauths |
| 1 | `BURSTY_SQUARE` | 3 s ON / 1 s OFF square wave (tunable) | Script-kiddy aireplay-ng `-0 0` loops |
| 2 | `MICROBURST_DEAUTH` | 1.2 s inject / 4 s silence loop | Real handshake grabber (Pwnagotchi, wifiphisher) — **this is the realistic one** |
| 3 | `MIXED_FRAME_TYPES` | MICROBURST cadence + random frame subtype per pkt | Multi-vector reconnaissance / scripted probe-flood |

### Dashboard Presets

| Button | Rate | Profile | Frame Mask | MAC Rand | RSSI Range | Use it for |
|---|---|---|---|---|---|---|
| 🎯 Handshake Grabber | 120 | 2 (MICROBURST) | deauth only | off | -80…-45 | Portfolio demo → guaranteed CRITICAL in ~10 s |
| ☕ Noisy Coffee Shop | 450 | 0 (CONSTANT) | all 4 types | on | -75…-35 | Calibrating against a realistic RF-dense normal baseline |
| 🏫 Classroom Safe | 30 | 0 (CONSTANT) | deauth only | off | -85…-40 | Low-rate sanity check the pipeline is wired correctly |

### Per-Venue Detection Thresholds (Quick Reference)

`config.h` Section 3 defaults are for a quiet residential bedroom at 2am. Tune these before deploying anywhere else. Use these numbers as starting points, then validate with the Handshake Grabber stress preset:

| # | Venue | `DEAUTH_THRESHOLD` | `ASSOC_THRESHOLD` | `RSSI_VAR_THRESHOLD` | Recommended validation profile |
|---|---|---|---|---|---|
| 1 | 🏡 Quiet Residential | 2.0 | 100 | 15.0 | MICROBURST @ 120 pkt/s |
| 2 | ☕ Coffee Shop / Coworking | 6.0 | 180 | 22.0 | BURSTY @ 220 pkt/s |
| 3 | 🛏️ Dorm Floor (weekday) | 18.0 | 260 | 30.0 | BURSTY @ 320 pkt/s |
| 4 | 🛏️ Dorm Floor (friday night) | 55.0 | 420 | 48.0 | BURSTY @ 480 pkt/s |
| 5 | 🏪 Retail Store (strip mall) | 4.0 | 150 | 18.0 | BURSTY @ 180 pkt/s |
| 6 | 🏫 Classroom (lecture) | 10.0 | 220 | 28.0 | BURSTY @ 280 pkt/s |
| 7 | 🏫 Auditorium / Assembly Hall | 30.0 | 380 | 42.0 | BURSTY @ 380 pkt/s |
| 8 | 🎮 LAN Party / Hackathon | 80.0 | 650 | 65.0 | MIXED @ 650 pkt/s |
| 9 | 📈 Conference / Trade Show Hall | 70.0 | 700 | 62.0 | MIXED @ 700 pkt/s |
| 10 | 🏭 Warehouse IoT (high density 2.4GHz) | 12.0 | 300 | 32.0 | BURSTY @ 300 pkt/s |
| 11 | 🌳 Outdoor Event (food truck rally) | 35.0 | 340 | 40.0 | BURSTY @ 340 pkt/s |
| 12 | 🏢 Small Office / Coworking (daytime) | 5.0 | 160 | 20.0 | BURSTY @ 200 pkt/s |

**15-minute venue calibration ritual (repeat on every new deploy):**
1. Set thresholds to the closest row above (e.g. ☕ Coffee Shop row)
2. Start stress using the "recommended validation profile" column
3. Wait 30 s → verify threat score hits **CRITICAL** (≥8.0) — if it only hits WARNING, lower the threshold by ~20% and retry
4. Stop stress → wait 60 s → verify score drops back to **SAFE** (≤2.5) — if it stays elevated, raise the threshold slightly
5. Done. The sweet spot is "realistic attack cadence = CRITICAL, noisy normal = SAFE."

### Runtime Tuning Knobs

Every value below has a **compile-time default** in `config.h` Section 3B and a **runtime override** via dashboard UI or `/stresstest` query params (all optional, auth-required for writes).

| Dashboard control | Query param | Compile default | Sentinels (use default) |
|---|---|---|---|
| Packet Rate slider | `rate` | `STRESS_DEFAULT_RATE_PKTS_PER_SEC` = 50 | `0` |
| Attack Profile dropdown | `profile` | `STRESS_DEFAULT_ATTACK_PROFILE` = 0 | `0xFF` / `255` |
| Frame-type checkboxes (bitmask: 1=deauth, 2=disassoc, 4=assoc, 8=probe) | `mask` | `STRESS_DEFAULT_FRAME_TYPE_MASK` = 1 | `0xFF` / `255` |
| RSSI min / max number inputs | `rssi_min`, `rssi_max` | -85 / -40 dBm | `0` |
| MAC Randomize checkbox | `mac_rand` | `0` (off) | `0xFF` / `255` |
| Burst timing (BURSTY profile) | `burst_on`, `burst_off` | 3000 / 1000 ms | `0` |
| μBurst timing (MICROBURST/MIXED) | `uburst_on`, `uburst_off` | 1200 / 4000 ms | `0` |
| Spread channels ±2 checkbox | `spread_ch` | `0` (off) | `0xFF` / `255` |
| Loop cadence slider | `loop_ms` | 1000 ms | `0` |

Dashboard values are kept in sync with device state via sentinel-aware hydration — if a field reports its sentinel value the UI falls back to the `config.h` defaults, so you always see the **effective** running value.

### Scripted / Headless Use

```bash
# Status (read-only, no auth required like /health)
curl -u admin:cybersentinel http://192.168.4.1/stresstest

# Start with portfolio demo preset
curl -u admin:cybersentinel \
  "http://192.168.4.1/stresstest?state=on&rate=120&profile=2&mask=1&rssi_min=-80&rssi_max=-45"

# Ramp up to noisy-coffee-shop baseline mid-run (state unchanged)
curl -u admin:cybersentinel \
  "http://192.168.4.1/stresstest?rate=450&profile=0&mask=15&rssi_min=-75&rssi_max=-35&mac_rand=1"

# Stop
curl -u admin:cybersentinel "http://192.168.4.1/stresstest?state=off"
```

All runtime config fields are also exported in `/data` as `stress_cfg_*` for programmatic capture + CSV export.

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
| Deauth / disassoc flood detection | ✅ Heuristic (EMA rate-based, threshold tunable) |
| Association / spoof flood detection | ✅ Heuristic (rate + MAC entropy) |
| Signal instability / jamming | ✅ EMA-smoothed RSSI variance detector |
| Rogue AP detection | ❌ Planned v2 (per-BSSID blocklist + known-AP OUI validation) |
| Per-MAC attribution (top N offenders) | ❌ Planned v2 (20-entry LRU MRU cache, sorted by pkt share) |
| Active mitigation (deauth-block, channel-ban) | ❌ **By design.** A $5 taped-to-ceiling passive sensor must never hold transmit privileges on the air it monitors. v2 mitigation lives on a *separate* coordinator, never the sensor. |
| Cloud sync / OTA updates | ❌ Planned v2 (HTTPS firmware binary pull + SPIFFS delta) |
| 5GHz / 6GHz band support | ❌ ESP32 hardware limitation. ESP32-C5 / ESP32-WiFi-7 target for v3. |
| Protected Management Frames (PMF, 802.11w) | ⚠️ Advisory-only. Modern APs with PMF enabled absorb most deauth frames; disassoc floods still partially bypass PMF on some firmware. Flagging still works, severity auto-reduced when RSSI + entropy pattern match "known-clean" PMF-enabled BSSID set (configurable in v2). |
| L3+ inspection (port scans, TLS fingerprinting, SQLi, C2) | ❌ **Out of project scope.** This is a *management-plane sensor*, not a NIDS. Run Suricata / Zeek on a RPi for L3+. |
| Forensic PCAP write | ❌ 4MB SPIFFS is too small. Export CSV logs (7-day rotating) + pair with a nearby Kismet drone if you need PCAP-level evidence. |

## Roadmap

| Version | Target | Key features |
|---|---|---|
| **v1.3.x** (current, bugfix) | — | Stability patches, queue-load health tuning, platformio.ini `esp32-s3` target |
| **v2.0** | 3-mo horizon | Rogue AP blocklist, per-MAC attribution (top 20 offenders), HTTPS OTA + delta SPIFFS, optional RPi Zero coordinator (single-pane fleet dashboard) |
| **v2.1** | 6-mo horizon | CSV → SIEM forwarder (Syslog RFC5424 + Splunk HEC endpoint), PMF-aware BSSID allowlist auto-load |
| **v3.0** | 12-mo horizon | ESP32-C5 5GHz capable target, multi-band 3-radio sensor reference design, tinyML anomaly classifier (on-device `.tflite` inference, ~6kB model budget) |

---

## License

MIT License — free to use, modify, distribute, and commercially use. Attribution appreciated but not legally required beyond the license text. See [LICENSE](LICENSE) for the full text.