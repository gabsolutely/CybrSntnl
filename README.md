# ESP-CyberSentinel

Open-source 802.11 management-frame anomaly sensor that runs entirely on a $5 ESP32.

Passively detects deauth floods, spoofed-association floods, and RSSI/jamming instability on 2.4GHz. No server, no cloud, no second device required. Includes a built-in stress-test harness with four attacker cadence profiles so detection can be validated on-site instead of taken on faith.

Not a replacement for Suricata or Zeek — it's the piece those tools don't cover, since they operate above the 802.11 management plane.

## Scope

| This is | This is not |
|---|---|
| An 802.11 management-plane anomaly sensor (deauth, disassoc, assoc-flood, RSSI jam) | A full NIDS/DPI engine — no TCP/IP inspection, no port-scan detection, no TLS fingerprinting |
| A $5, battery-sized, zero-infrastructure edge sensor | A commercial WIDS (Cisco CleanAir, MetaGeek, AirMagnet) — those are multi-radio, 5GHz-capable, PCAP-capable, and priced accordingly |
| Single-radio, channel-time-sliced (80% home / 20% blitz), built for detection + alarm | Forensic-grade capture — PCAP isn't written to the 4MB SPIFFS, and frames on non-home channels are missed by design during the 20% blitz window |
| 2.4GHz only (ESP32 hardware limit) | 5GHz/6GHz capable |
| MIT-licensed and fully auditable | A black-box appliance with a support contract |

If the requirement is full L3+ inspection, run Suricata on a Pi. This project is for the specific gap most racked NIDS setups leave open: cheap, disposable, single-purpose Wi-Fi management-frame monitoring.

## Why this exists

Most Wi-Fi threat detection today assumes desktop-class hardware — gigabytes of RAM, a GPU, a full OS, just to parse network frames. Reasonable for a lot of use cases, but overkill for a narrow, well-defined problem: watching for management-frame attacks on a home or small-venue network.

This project is built on the opposite assumption — that a single $5 ESP32, with 520KB of SRAM, is enough to run a full detection pipeline (sniffing, feature extraction, threat scoring, a live dashboard) if the architecture doesn't waste any of that budget.

**Why it matters in practice:** modern deauth attacks usually aren't loud floods anymore — they're 1–2 second micro-bursts, just enough to force a handshake, then silence. A laptop reconnects in a couple seconds and the whole thing looks like a network blip to a person watching. A headless device — a camera, a sensor, anything without retry logic in its firmware — just drops and stays dropped, with nothing surfacing the cause. This sensor exists to catch that pattern while it's happening, not after the fact.

## Architecture

**80/20 radio budget.** The radio is split 80% raw promiscuous sniffing, 20% background dashboard updates, so neither task starves the other. This split holds across all radio modes — auto-hop, manual channel, Threat Lock, and Threat Lock cooldown.

**ISR-direct ingestion.** Frame capture happens inside the packet-capture ISR itself, writing into an async FreeRTOS ring buffer. High-velocity floods (100+ frames/sec) go straight into the queue from interrupt context, so nothing is lost while userland tasks are busy. Core 1 drains the queue in order.

**Mutex-isolated state.** All cross-core shared state (threat score, feature vectors, channel mode, Threat Lock status) sits behind a single mutex with bounded timeouts on every access. Heap guards are in place on every task — if free heap drops below ~20KB, tasks yield instead of crashing.

**Dumb backend, smart client.** The ESP32 only ever emits numeric primitives over JSON (`threat_score`, `packet_rate`, etc.). Formatting, chart rendering, and label generation all happen client-side, since heap is the scarcest resource on the chip and a browser has plenty to spare.

**Dual-core split:**
- Core 0 — radio controller (channel time-slicing, Threat Lock auto-engage)
- Core 1 — feature extraction, threat scoring, dashboard, logging

## What it detects

EMA-smoothed heuristics, not ML:

- **Deauth / disassoc floods** — rate-based, tunable threshold
- **Spoofed-association floods** — high MAC entropy combined with high assoc rate
- **RSSI instability / jamming** — high signal variance without corresponding channel congestion

## Features

- 802.11 management-plane heuristic detection (rate + entropy + RSSI-variance)
- 4 attack-cadence self-test profiles (constant, bursty, microburst, mixed) for on-site validation
- Runtime-tunable detection knobs via dashboard or `/stresstest` API
- 3 one-click dashboard presets for common environments
- Live threshold tuning panel — adjust deauth/assoc/RSSI-variance thresholds from the dashboard and persist to NVS (internal builds only; core builds show the compiled defaults read-only)
- Real-time dashboard served from a standalone AP, with system info (CPU, heap, flash, network, storage, active API endpoints) surfaced directly in the UI
- Guerilla Sweep channel time-slicing (keeps the dashboard responsive during a full sweep)
- Threat Lock — auto-engages above a threat score of 7.0, pins 80% of radio time to the offending channel
- Manual channel override with a full labeled 13-channel selector (non-overlapping channels 1/6/11 flagged)
- Recommendations panel — surfaces mitigation guidance tied to the current or most recent detected threat
- Last Event summary panel
- Data export: JSON, CSV, and a generated report, in addition to SPIFFS-based 7-day rotating CSV logs
- HTTP Basic Auth on all write endpoints and telemetry reads (`/health` stays open for monitoring)
- Dual PlatformIO build environments — `core` (stress-sim and threshold-persistence compiled out) and `internal` (full harness)

## Hardware

- Any ESP32-WROOM or ESP32-WROVER board, 4MB flash minimum, PSRAM optional
- Micro-USB cable — nothing else required for base functionality
- Optional, defined in `include/config.h`:
  - Status LED (GPIO 2, enabled by default on most devkits)
  - RGB threat LED (pins 17/13/14)
  - Override pushbutton (pin 15)
  - Buzzer (pin 16)
  - SSD1306 128×64 I²C OLED (pins 21/22)

## Getting started

Requires [PlatformIO](https://platformio.org/).

```bash
git clone https://github.com/<your-handle>/CyberSentinel-Core.git
cd CyberSentinel-Core/CybrSntnl

# Build with the stress-test harness enabled
pio run -e internal -t upload

# Upload dashboard assets — required, dashboard lives on SPIFFS not firmware
pio run -e internal -t uploadfs
```

For a release build without the stress injector (recommended if deploying somewhere semi-public), use `-e core` instead. The injector is compiled out entirely, and the dashboard's Stress Test panel becomes read-only.

**Accessing the dashboard:**
1. Connect to the AP `CyberSentinel-Fallback` / `fallback123456` — change both before deploying anywhere semi-public
2. Go to `http://192.168.4.1`
3. Log in with HTTP Basic Auth: `admin` / `cybersentinel` — change this too (`config.h`, Section 5)
4. Run Stress Test → Handshake Grabber preset → Start, and confirm it reaches CRITICAL within 20s. If it doesn't, `DEAUTH_THRESHOLD` is already too high for the environment — lower it and retry.

## Before deploying anywhere

This is a deliberately narrow-scope edge sensor, not a production security appliance.

- **Not a substitute for a real L3+ IDS/IPS.** Heuristics on ESP32-class hardware will false-positive in RF-dense venues (conferences, dorms, LAN parties). Treat it as an alarm, not forensic evidence.
- **Per-venue tuning is required, not optional.** Defaults in `config.h` are tuned for a quiet residential room. See the threshold table below.
- **Single-radio blind spot.** The 20% blitz window means ~360ms of missed coverage on non-home channels every 3 seconds, by design. A burst landing squarely in three consecutive blitz windows will be missed. Fine for an alarm; not fine for forensics.
- **2.4GHz only.** 5GHz/6GHz attacks — which most enterprise networks actually run on — are invisible to this hardware.
- **Check local regulations.** Promiscuous-mode capture legality varies by jurisdiction. Only monitor networks you own or have explicit permission to monitor.
- **Passive only, for now.** The current build never transmits, blocks, or spoofs. Active mitigation is being researched for a future release — if that ships, it will be a deliberate, separate opt-in, not a default.

**Pre-flight checklist:**
1. Change `AP_SSID` / `AP_PASS` in `config.h`, Section 5
2. Change `DASH_AUTH_USER` / `DASH_AUTH_PASS`, same section
3. Run the 15-minute venue calibration (below) before trusting the alarm in a new location
4. Confirm `DEVELOPMENT_MODE` is `0` in release builds
5. Flash both firmware and filesystem — skipping `uploadfs` leaves the dashboard blank

## Stress test harness

A tunable synthetic attack injector runs inside the detection pipeline itself — no second device, no radio transmission involved. It writes fake frame metadata into the same queue the real ISR feeds, so the feature extractor, scorer, and Threat Lock state machine all react exactly as they would to a real capture.

**Build modes:**

| Environment | Stress sim | Behavior |
|---|---|---|
| `core` (default) | Off | Injector compiled out entirely; dashboard panel read-only |
| `internal` | On | Full dashboard UI, `/stresstest` API, `/data` export |

This is gated at build time on purpose — shipping the injector in a release build would let anyone with AP credentials self-DoS the monitoring pipeline.

**Attack profiles:**

| # | Name | Behavior | Analogue |
|---|---|---|---|
| 0 | Constant | Flat rate | Static jammer, broken driver loop |
| 1 | Bursty | 3s on / 1s off square wave | `aireplay-ng -0 0` style loops |
| 2 | Microburst | 1.2s inject / 4s silence | Realistic handshake grabber (Pwnagotchi, wifiphisher) |
| 3 | Mixed | Microburst timing, randomized frame subtypes | Multi-vector reconnaissance |

**Dashboard presets:**

| Preset | Rate | Profile | Use |
|---|---|---|---|
| Handshake Grabber | 120 pkt/s | Microburst | Realistic single-run validation |
| Noisy Coffee Shop | 450 pkt/s | Constant, all frame types | Calibrating against a busy baseline |
| Classroom Safe | 30 pkt/s | Constant, deauth only | Low-rate pipeline sanity check |

**Per-venue thresholds** (starting points — validate with the Handshake Grabber preset after setting):

| Venue | Deauth threshold | Assoc threshold | RSSI variance |
|---|---|---|---|
| Quiet residential | 2.0 | 100 | 15.0 |
| Coffee shop / coworking | 6.0 | 180 | 22.0 |
| Dorm floor (weekday) | 18.0 | 260 | 30.0 |
| Dorm floor (weekend night) | 55.0 | 420 | 48.0 |
| Retail store | 4.0 | 150 | 18.0 |
| Classroom (lecture) | 10.0 | 220 | 28.0 |
| Auditorium | 30.0 | 380 | 42.0 |
| LAN party / hackathon | 80.0 | 650 | 65.0 |
| Conference hall | 70.0 | 700 | 62.0 |
| Warehouse IoT (dense 2.4GHz) | 12.0 | 300 | 32.0 |
| Outdoor event | 35.0 | 340 | 40.0 |
| Small office (daytime) | 5.0 | 160 | 20.0 |

**Calibration ritual (repeat for each new deployment):**
1. Set thresholds to the closest row above
2. Run the recommended validation profile for ~30s and confirm the score reaches CRITICAL (≥8.0) — if it only reaches WARNING, lower thresholds ~20% and retry
3. Stop, wait 60s, confirm the score drops back to SAFE (≤2.5) — if it stays elevated, raise thresholds slightly
4. Target state: realistic attack cadence reads CRITICAL, normal venue noise reads SAFE

**Scripted use:**

```bash
# Read status (no auth required, like /health)
curl -u admin:cybersentinel http://192.168.4.1/stresstest

# Start with the portfolio-demo preset
curl -u admin:cybersentinel \
  "http://192.168.4.1/stresstest?state=on&rate=120&profile=2&mask=1&rssi_min=-80&rssi_max=-45"

# Stop
curl -u admin:cybersentinel "http://192.168.4.1/stresstest?state=off"
```

All runtime config is also exported in `/data` as `stress_cfg_*` fields for CSV/programmatic capture.

## Current limitations

| Capability | Status |
|---|---|
| Deauth / disassoc flood detection | Implemented (EMA rate-based) |
| Association / spoof flood detection | Implemented (rate + entropy) |
| Signal instability / jamming | Implemented (EMA RSSI variance) |
| Rogue AP detection | Planned — v2 |
| Per-MAC attribution | Planned — v2 |
| Active mitigation | Researching feasibility — no timeline yet. Note this is a shift from the original passive-only design stance; nothing in the current build transmits or mitigates |
| Cloud sync / OTA | Planned — v2 |
| 5GHz / 6GHz | Not possible on this hardware — targeted for v3 (ESP32-C5) |
| PMF (802.11w) awareness | Advisory only — severity is not currently reduced for PMF-protected networks |
| L3+ inspection | Out of scope — this is a management-plane sensor, not a NIDS |
| Forensic PCAP capture | Not supported — 4MB SPIFFS is too small; use the CSV logs, or pair with a dedicated capture tool if PCAP-level evidence is needed |

## Roadmap

| Version | Target | Focus |
|---|---|---|
| v1.3.x (current) | — | Stability, queue-load health tuning, ESP32-S3 target |
| v2.0 | TBD | Rogue AP blocklist, per-MAC attribution, OTA updates, optional Pi coordinator |
| v2.1 | TBD | SIEM forwarding (Syslog/Splunk), PMF-aware allowlisting |
| v3.0 | TBD | ESP32-C5 5GHz target, multi-radio reference design, on-device tinyML classifier |

## License

MIT. Free to use, modify, distribute, and use commercially. Attribution appreciated but not required beyond the license text — see [LICENSE](LICENSE).