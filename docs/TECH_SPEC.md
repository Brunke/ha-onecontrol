# OneControl HACS Integration — Technical Specification

## 1. Purpose and Scope

`ha_onecontrol` is a Home Assistant BLE integration for Lippert/LCI OneControl gateways. It provides native entity discovery and control for relays, lights, HVAC zones, covers, tanks, generator telemetry, and diagnostics.

This document describes the current HA-native implementation and excludes mobile bridge specifics.

## 2. Integration Snapshot

- **Domain:** `ha_onecontrol`
- **Primary runtime component:** `OneControlCoordinator`
- **Platforms:** `binary_sensor`, `button`, `climate`, `light`, `sensor`, `switch`
- **Transport:** BLE GATT via Home Assistant Bluetooth stack
- **Coordinator mode:** push/event-driven (`update_interval=None`)

## 3. Configuration and Entry Setup

- BLE discovery uses Lippert manufacturer advertisement data.
- Config flow supports two pairing models:
  - push-to-pair gateways
  - legacy PIN gateways
- Core credentials:
  - `gateway_pin` (required)
  - `bluetooth_pin` (optional override)

## 4. Runtime Lifecycle

1. Entry setup creates coordinator and forwards platforms.
2. Initial connect runs as background task (non-blocking startup).
3. BLE session authenticates and enables notifications.
4. COBS/CRC decode pipeline parses protocol events.
5. Parsed state maps are updated and listener callbacks refresh entities.

## 5. Protocol and Transport Model

### 5.1 Authentication/session flow

The coordinator executes a two-step authentication sequence before normal event handling.

- **Auth service:** `00000010-0200-a58e-e411-afe28044e62c`
- **Seed characteristic:** `00000011-0200-a58e-e411-afe28044e62c`
- **Unlock status characteristic:** `00000012-0200-a58e-e411-afe28044e62c`
- **Key characteristic:** `00000013-0200-a58e-e411-afe28044e62c`
- **Auth status characteristic:** `00000014-0200-a58e-e411-afe28044e62c`

Session timing constants include `AUTH_TIMEOUT=10s`, `UNLOCK_VERIFY_DELAY=0.5s`, `NOTIFICATION_ENABLE_DELAY=0.2s`, and `BLE_MTU_SIZE=185`.

### 5.2 Frame handling

- COBS framing with CRC checks
- typed event parsing for relay/light/HVAC/tank/system events
- unknown or invalid frame discard with counters

Data transport uses:

- **Data service:** `00000030-0200-a58e-e411-afe28044e62c`
- **Write characteristic:** `00000033-0200-a58e-e411-afe28044e62c`
- **Read/notify characteristic:** `00000034-0200-a58e-e411-afe28044e62c`

MyRvLink event byte identifiers include (non-exhaustive):

- `0x01` gateway info, `0x02` command response, `0x05/0x06` relay, `0x08` dimmable, `0x09` RGB,
- `0x0B` HVAC, `0x0C/0x1B` tank, `0x0D/0x0E` h-bridge, `0x0F` hour meter, `0x20` RTC.

### 5.3 Identity model

- Canonical device join key: `(table_id, device_id)` encoded as `tt:dd`
- all per-device runtime maps and metadata binding use this key

## 6. State and Entity Model

- Switch entities map relay actions and status.
- Light entities include dimmable and RGB variants.
- Climate entities model per-zone HVAC mode/fan/setpoint state.
- Sensor/binary/button entities expose tanks, system status, lockout, diagnostics, and controls.

## 7. Command and Control Surface

- Relay and light action commands route through coordinator write path.
- HVAC command path includes pending-window suppression and setpoint retry logic.
- Metadata refresh and lockout/maintenance actions are exposed via platform controls.

Command builder wire format is:

`[cmd_id_lsb][cmd_id_msb][command_type][payload...]`

Key command types:

- `0x01` GetDevices
- `0x02` GetDevicesMetadata
- `0x40` switch action
- `0x41` h-bridge action
- `0x42` generator action
- `0x43` dimmable action
- `0x44` RGB action
- `0x45` HVAC action

Metadata response handling is explicitly correlated by cmd-id with response type semantics:

- `0x01` success-multi (staging)
- `0x81` success-complete (commit)
- `0x82` failure (including `0x0F` rejection path with retry scheduling)

Staged metadata commit requires count/CRC consistency and guards against cross-command contamination via pending cmd-id maps.

## 8. Reliability and Recovery

- background startup connection pattern
- reconnect backoff with cap
- heartbeat/liveness maintenance
- stale-stream timeout reconnection
- command-correlation counters for drift detection

Core operational timers:

- `HEARTBEAT_INTERVAL=5s`
- `RECONNECT_BACKOFF_BASE=5s`, `RECONNECT_BACKOFF_CAP=120s`
- `STALE_CONNECTION_TIMEOUT=300s`
- HVAC guard/retry constants: `8s` (mode/fan), `20s` (setpoint), `70s` (preset), setpoint retry delay `5s`, max retries `3`
- Switch optimistic guard: `1s`

## 9. Diagnostics and Observability

- integration diagnostics export coordinator state and protocol counters
- metadata correlation and unknown-command statistics retained for troubleshooting
- entity availability reflects connection and data freshness

## 10. Security and Safety Notes

- cover behavior is conservative and state-oriented for movement safety
- sensitive key-schedule values are not stored as plain constants
- legacy PIN behavior depends on host BLE capabilities

## 11. Evolution Notes (Commit History)

Recent trajectory includes:

- metadata orchestration hardening (gating, staged commit, retry behavior)
- startup/connect resiliency improvements
- HVAC command parity improvements
- relay bounce suppression
- migration to `ha_onecontrol` domain naming

## 12. Known Constraints

- legacy PIN paths may be constrained by adapter/proxy stack behavior
- gateway firmware/protocol variance can require parser updates
- friendly naming depends on successful metadata completion

## 13. Extension Guidelines

1. Keep `(table_id, device_id)` as the single device identity primitive.
2. Track command ids explicitly for multi-command concurrency safety.
3. Stage multi-part payloads and commit only on validated terminal frames.
4. Add observability counters before introducing new protocol surfaces.
5. Use guarded optimistic windows where delayed echoes are common.
