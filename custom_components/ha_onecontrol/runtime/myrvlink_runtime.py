"""MyRvLink/BLE runtime orchestration.

This runtime owns BLE connect/auth retry sequencing while preserving the
coordinator's public API and existing parsing/state semantics.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from .ids_can_runtime import IdsCanRuntime
from ..ble_agent import remove_bond
from ..protocol.function_names import get_friendly_name
from ..protocol.events import (
    CoverStatus,
    DeviceLock,
    GatewayInformation,
    DeviceMetadata,
    DeviceOnline,
    DimmableLight,
    GeneratorStatus,
    HourMeter,
    RelayStatus,
    RgbLight,
    TankLevel,
    parse_get_devices_response,
    parse_metadata_response,
)

if TYPE_CHECKING:
    from ..coordinator import OneControlCoordinator

_LOGGER = logging.getLogger(__name__)


class MyRvLinkRuntime:
    """Runtime for BLE/MyRvLink connection orchestration."""

    def __init__(self, coordinator: OneControlCoordinator, ids_runtime: IdsCanRuntime) -> None:
        self._c = coordinator
        self._ids_runtime = ids_runtime

    async def send_metadata_request(self, table_id: int) -> None:
        """Send GetDevicesMetadata for a single table ID."""
        if not self._c._supports_metadata_requests:
            return
        cmd = self._c._cmd.build_get_devices_metadata(table_id)
        cmd_id = int.from_bytes(cmd[0:2], "little")
        self.record_pending_metadata_cmd(cmd_id, table_id, max_pending=128)
        self._c._pending_metadata_entries.pop(cmd_id, None)
        self._c._metadata_rejected_tables.discard(table_id)
        self._c._metadata_requested_tables.add(table_id)
        try:
            await self._c.async_send_command(cmd)
            _LOGGER.info("Sent GetDevicesMetadata for table %d (cmdId=%d)", table_id, cmd_id)
        except Exception as exc:
            self._c._pending_metadata_cmdids.pop(cmd_id, None)
            self._c._pending_metadata_sent_at.pop(cmd_id, None)
            self._c._pending_metadata_entries.pop(cmd_id, None)
            self._c._metadata_requested_tables.discard(table_id)
            _LOGGER.warning("Failed to send metadata request: %s", exc)

    async def retry_metadata_after_rejection(self, table_id: int) -> None:
        """Retry GetDevicesMetadata 10s after a rejection."""
        await asyncio.sleep(10.0)
        if not self._c._supports_metadata_requests:
            return
        if not self._c._connected:
            return
        if table_id in self._c._metadata_loaded_tables:
            return
        _LOGGER.debug("Retrying metadata for table_id=%d after 0x0f rejection", table_id)
        self._c._metadata_requested_tables.discard(table_id)
        if table_id not in self._c._get_devices_loaded_tables:
            self._c._cmd_correlation_stats["metadata_waiting_get_devices"] += 1
            _LOGGER.debug(
                "Retry for metadata table %d deferred - waiting for GetDevices completion",
                table_id,
            )
            return
        await self.send_metadata_request(table_id)

    async def send_initial_get_devices(self) -> None:
        """Delay then send GetDevices wake-up command."""
        await asyncio.sleep(0.5)
        await self.do_send_initial_get_devices()

    async def do_send_initial_get_devices(self) -> None:
        """Send initial GetDevices if connection/auth state allows."""
        if self._c._initial_get_devices_sent:
            return
        if not self._c._connected or not self._c._authenticated:
            return
        table_id = self._c._select_get_devices_table_id()
        if table_id is None:
            return
        try:
            cmd = self._c._cmd.build_get_devices(table_id)
            cmd_id = int.from_bytes(cmd[0:2], "little")
            self.record_pending_get_devices_cmd(cmd_id, table_id, max_pending=128)
            await self._c.async_send_command(cmd)
            self._c._initial_get_devices_sent = True
            _LOGGER.debug(
                "Initial GetDevices sent for table %d (cmdId=%d)",
                table_id,
                cmd_id,
            )
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning("Initial GetDevices failed: %s", exc)

    async def request_metadata_after_delay(self, table_id: int) -> None:
        """Wait then request metadata, gated by completion/rejection state."""
        if not self._c._supports_metadata_requests:
            return
        await asyncio.sleep(1.5)
        if table_id in self._c._metadata_loaded_tables:
            return
        if table_id in self._c._metadata_rejected_tables:
            return
        if table_id in self._c._metadata_requested_tables:
            return
        if table_id not in self._c._get_devices_loaded_tables:
            self._c._cmd_correlation_stats["metadata_waiting_get_devices"] += 1
            _LOGGER.debug(
                "Metadata request deferred for table %d - waiting for GetDevices completion",
                table_id,
            )
            return
        await self.send_metadata_request(table_id)

    def ensure_metadata_for_table(self, table_id: int) -> None:
        """Schedule metadata request for newly observed table IDs."""
        if not self._c._supports_metadata_requests:
            return
        if table_id == 0:
            return
        if (
            table_id in self._c._metadata_loaded_tables
            or table_id in self._c._metadata_rejected_tables
            or table_id in self._c._metadata_requested_tables
        ):
            return
        if table_id not in self._c._get_devices_loaded_tables:
            self._c._cmd_correlation_stats["metadata_waiting_get_devices"] += 1
            _LOGGER.debug(
                "Observed table_id=%d but delaying metadata until GetDevices completes",
                table_id,
            )
            return
        _LOGGER.info("Requesting metadata for observed table_id=%d", table_id)
        self._c.hass.async_create_task(self.send_metadata_request(table_id))

    def handle_gateway_information(self, event: GatewayInformation) -> None:
        """Apply GatewayInformation and manage metadata CRC/scheduling behavior."""
        _LOGGER.debug(
            "GatewayInfo: table_id=%d, devices=%d, table_crc=0x%08x, metadata_crc=0x%08x",
            event.table_id,
            event.device_count,
            event.device_table_crc,
            event.device_metadata_table_crc,
        )

        crc = event.device_metadata_table_crc
        if crc != 0 and crc == self._c._last_metadata_crc:
            self._c._metadata_loaded_tables.add(event.table_id)
            _LOGGER.debug(
                "Metadata CRC unchanged (0x%08x), skipping re-request for table %d",
                crc,
                event.table_id,
            )
        elif (
            self._c._last_metadata_crc is not None
            and crc != self._c._last_metadata_crc
            and event.table_id in self._c._metadata_loaded_tables
        ):
            _LOGGER.info(
                "Metadata CRC changed (0x%08x -> 0x%08x), invalidating table %d",
                self._c._last_metadata_crc,
                crc,
                event.table_id,
            )
            self._c._last_metadata_crc = None
            prefix = f"{event.table_id:02x}:"
            for key in list(self._c._metadata_raw):
                if key.startswith(prefix):
                    del self._c._metadata_raw[key]
                    self._c.device_names.pop(key, None)
            self._c._metadata_requested_tables.discard(event.table_id)
            self._c._metadata_loaded_tables.discard(event.table_id)
            self._c._metadata_rejected_tables.discard(event.table_id)

        self._c.gateway_info = event

        if not self._c._initial_get_devices_sent:
            self._c.hass.async_create_task(self.do_send_initial_get_devices())

        if (
            self._c._supports_metadata_requests
            and event.table_id not in self._c._metadata_loaded_tables
            and event.table_id not in self._c._metadata_requested_tables
        ):
            if event.table_id in self._c._get_devices_loaded_tables:
                self._c.hass.async_create_task(self.request_metadata_after_delay(event.table_id))
            else:
                self._c._cmd_correlation_stats["metadata_waiting_get_devices"] += 1
                _LOGGER.debug(
                    "GatewayInfo table %d waiting for GetDevices completion before metadata request",
                    event.table_id,
                )

    def process_metadata(self, meta: DeviceMetadata) -> None:
        """Store metadata rows and resolve canonical friendly names."""
        key = f"{meta.table_id:02x}:{meta.device_id:02x}"
        self._c._metadata_raw[key] = meta
        name = get_friendly_name(meta.function_name, meta.function_instance)
        self._c.device_names[key] = name
        self._c._metadata_loaded_tables.add(meta.table_id)
        if (
            self._c.gateway_info is not None
            and meta.table_id == self._c.gateway_info.table_id
            and self._c.gateway_info.device_metadata_table_crc != 0
        ):
            self._c._last_metadata_crc = self._c.gateway_info.device_metadata_table_crc
        _LOGGER.info(
            "Metadata: %s -> func=%d inst=%d -> %s",
            key.upper(),
            meta.function_name,
            meta.function_instance,
            name,
        )

    def reset_protocol_tracking_state(self) -> None:
        """Clear protocol-level command/metadata tracking on disconnect."""
        self._c._metadata_requested_tables.clear()
        self._c._metadata_loaded_tables.clear()
        self._c._metadata_rejected_tables.clear()
        self._c._metadata_retry_counts.clear()
        self._c._pending_metadata_cmdids.clear()
        self._c._pending_metadata_sent_at.clear()
        self._c._pending_metadata_entries.clear()
        self._c._pending_get_devices_cmdids.clear()
        self._c._pending_get_devices_sent_at.clear()
        self._c._get_devices_loaded_tables.clear()
        self._c._unknown_command_counts.clear()
        self._c._initial_get_devices_sent = False

    def record_pending_get_devices_cmd(self, cmd_id: int, table_id: int, max_pending: int) -> None:
        """Track in-flight GetDevices command IDs with bounded retention."""
        now = time.monotonic()
        self._c._pending_get_devices_cmdids[cmd_id] = table_id
        self._c._pending_get_devices_sent_at[cmd_id] = now
        while len(self._c._pending_get_devices_cmdids) > max_pending:
            oldest_cmd_id = next(iter(self._c._pending_get_devices_cmdids))
            self._c._pending_get_devices_cmdids.pop(oldest_cmd_id, None)
            self._c._pending_get_devices_sent_at.pop(oldest_cmd_id, None)
            self._c._cmd_correlation_stats["pending_cmdid_pruned"] += 1
        self._c._cmd_correlation_stats["pending_get_devices_peak"] = max(
            self._c._cmd_correlation_stats["pending_get_devices_peak"],
            len(self._c._pending_get_devices_cmdids),
        )

    def record_pending_metadata_cmd(self, cmd_id: int, table_id: int, max_pending: int) -> None:
        """Track in-flight metadata command IDs with bounded retention."""
        now = time.monotonic()
        self._c._pending_metadata_cmdids[cmd_id] = table_id
        self._c._pending_metadata_sent_at[cmd_id] = now
        while len(self._c._pending_metadata_cmdids) > max_pending:
            oldest_cmd_id = next(iter(self._c._pending_metadata_cmdids))
            self._c._pending_metadata_cmdids.pop(oldest_cmd_id, None)
            self._c._pending_metadata_sent_at.pop(oldest_cmd_id, None)
            self._c._pending_metadata_entries.pop(oldest_cmd_id, None)
            self._c._cmd_correlation_stats["pending_cmdid_pruned"] += 1

    def prune_pending_command_state(self, stale_timeout_s: float) -> None:
        """Drop stale pending cmdIds so late/missing responses do not accumulate."""
        cutoff = time.monotonic() - stale_timeout_s

        stale_get_devices = [
            cmd_id
            for cmd_id, sent_at in self._c._pending_get_devices_sent_at.items()
            if sent_at < cutoff
        ]
        for cmd_id in stale_get_devices:
            self._c._pending_get_devices_sent_at.pop(cmd_id, None)
            self._c._pending_get_devices_cmdids.pop(cmd_id, None)
            self._c._cmd_correlation_stats["pending_cmdid_pruned"] += 1

        stale_metadata = [
            cmd_id
            for cmd_id, sent_at in self._c._pending_metadata_sent_at.items()
            if sent_at < cutoff
        ]
        for cmd_id in stale_metadata:
            self._c._pending_metadata_sent_at.pop(cmd_id, None)
            self._c._pending_metadata_cmdids.pop(cmd_id, None)
            self._c._pending_metadata_entries.pop(cmd_id, None)
            self._c._cmd_correlation_stats["pending_cmdid_pruned"] += 1

    def bump_unknown_cmd_count(self, cmd_id: int, max_unknown: int) -> int:
        """Increment unknown cmdId counter and bound map size."""
        count = self._c._unknown_command_counts.get(cmd_id, 0) + 1
        self._c._unknown_command_counts[cmd_id] = count
        while len(self._c._unknown_command_counts) > max_unknown:
            self._c._unknown_command_counts.pop(next(iter(self._c._unknown_command_counts)))
            self._c._cmd_correlation_stats["unknown_cmdids_pruned"] += 1
        return count

    def handle_metadata_for_event(self, event: object) -> None:
        """Route metadata processing/requests for event payload types."""
        if isinstance(event, list):
            for item in event:
                self.handle_metadata_for_event(item)
            return

        if isinstance(event, DeviceMetadata):
            self.process_metadata(event)
            return

        if isinstance(
            event,
            (
                RelayStatus,
                DimmableLight,
                RgbLight,
                CoverStatus,
                TankLevel,
                DeviceOnline,
                DeviceLock,
                GeneratorStatus,
                HourMeter,
            ),
        ):
            self.ensure_metadata_for_table(event.table_id)

    def handle_command_frame(self, frame: bytes) -> bool:
        """Handle standard MyRvLink command envelopes.

        Returns True when the frame is consumed and should not be parsed as a
        regular state/event payload.
        """
        if not frame or frame[0] != 0x02:
            return False

        if len(frame) < 4:
            return True

        def _resolve_pending_cmd_id(raw_cmd_id: int) -> int:
            if (
                raw_cmd_id in self._c._pending_get_devices_cmdids
                or raw_cmd_id in self._c._pending_metadata_cmdids
            ):
                return raw_cmd_id
            swapped = ((raw_cmd_id & 0xFF) << 8) | ((raw_cmd_id >> 8) & 0xFF)
            if (
                swapped in self._c._pending_get_devices_cmdids
                or swapped in self._c._pending_metadata_cmdids
            ):
                return swapped
            return raw_cmd_id

        cmd_id = (frame[1] & 0xFF) | ((frame[2] & 0xFF) << 8)
        cmd_id = _resolve_pending_cmd_id(cmd_id)
        response_type = frame[3] & 0xFF

        if response_type == 0x81:
            completed_get_devices_table = self._c._pending_get_devices_cmdids.pop(cmd_id, None)
            self._c._pending_get_devices_sent_at.pop(cmd_id, None)
            if completed_get_devices_table is not None:
                self._c._cmd_correlation_stats["get_devices_completed"] += 1
                self._c._get_devices_loaded_tables.add(completed_get_devices_table)
                if (
                    self._c._supports_metadata_requests
                    and completed_get_devices_table not in self._c._metadata_loaded_tables
                    and completed_get_devices_table not in self._c._metadata_requested_tables
                ):
                    self._c.hass.async_create_task(
                        self.send_metadata_request(completed_get_devices_table)
                    )
                return True

            completed_table = self._c._pending_metadata_cmdids.pop(cmd_id, None)
            self._c._pending_metadata_sent_at.pop(cmd_id, None)
            if completed_table is not None and len(frame) >= 8:
                response_crc = int.from_bytes(frame[4:8], "big")
                response_count = frame[8] & 0xFF if len(frame) >= 9 else None
                staged_entries = self._c._pending_metadata_entries.pop(cmd_id, {})
                staged_count = len(staged_entries)
                expected_crc = (
                    self._c.gateway_info.device_metadata_table_crc
                    if self._c.gateway_info is not None
                    else 0
                )
                if expected_crc != 0 and response_crc != expected_crc:
                    self._c._cmd_correlation_stats["metadata_commit_crc_mismatch"] += 1
                    self._c._metadata_loaded_tables.discard(completed_table)
                    self._c._metadata_requested_tables.discard(completed_table)
                    self._c._last_metadata_crc = None
                elif response_count is not None and response_count != staged_count:
                    self._c._cmd_correlation_stats["metadata_commit_count_mismatch"] += 1
                    self._c._metadata_loaded_tables.discard(completed_table)
                    self._c._metadata_requested_tables.discard(completed_table)
                    self._c._last_metadata_crc = None
                else:
                    for meta in staged_entries.values():
                        self._c._process_metadata(meta)
                    self._c._metadata_loaded_tables.add(completed_table)
                    self._c._metadata_rejected_tables.discard(completed_table)
                    self._c._last_metadata_crc = response_crc
                    self._c._cmd_correlation_stats["metadata_commit_success"] += 1
            return True

        if response_type == 0x82:
            rejected_table = self._c._pending_metadata_cmdids.pop(cmd_id, None)
            self._c._pending_metadata_sent_at.pop(cmd_id, None)
            self._c._pending_metadata_entries.pop(cmd_id, None)
            if rejected_table is not None:
                error_code = frame[4] & 0xFF if len(frame) >= 5 else -1
                if error_code == 0x0F:
                    self._c._metadata_rejected_tables.discard(rejected_table)
                    retry_count = self._c._metadata_retry_counts.get(rejected_table, 0) + 1
                    self._c._metadata_retry_counts[rejected_table] = retry_count
                    self._c._cmd_correlation_stats["metadata_retry_scheduled"] += 1
                    self._c.hass.async_create_task(
                        self.retry_metadata_after_rejection(rejected_table)
                    )
                else:
                    self._c._metadata_requested_tables.discard(rejected_table)
                    self._c._metadata_rejected_tables.add(rejected_table)
            else:
                gd_table = self._c._pending_get_devices_cmdids.pop(cmd_id, None)
                self._c._pending_get_devices_sent_at.pop(cmd_id, None)
                if gd_table is not None:
                    self._c._cmd_correlation_stats["get_devices_rejected"] += 1
                    self._c._get_devices_loaded_tables.discard(gd_table)
                else:
                    self._c._cmd_correlation_stats["command_error_unknown"] += 1
                    self.bump_unknown_cmd_count(cmd_id, max_unknown=512)
            return True

        if response_type == 0x01:
            if cmd_id in self._c._pending_get_devices_cmdids:
                identities = parse_get_devices_response(frame)
                if identities:
                    self._c._cmd_correlation_stats["get_devices_identity_rows"] += len(identities)
                for identity in identities:
                    key = f"{identity.table_id:02x}:{identity.device_id:02x}"
                    self._c._device_identities[key] = identity
                    self._c._apply_external_name(key, identity)
                return True

            if cmd_id not in self._c._pending_metadata_cmdids:
                self._c._cmd_correlation_stats["metadata_success_multi_discarded_unknown"] += 1
                self.bump_unknown_cmd_count(cmd_id, max_unknown=512)
                return True

            self._c._cmd_correlation_stats["metadata_success_multi_accepted"] += 1
            staged = self._c._pending_metadata_entries.setdefault(cmd_id, {})
            added = 0
            try:
                parsed_metadata = parse_metadata_response(frame)
            except Exception:
                self._c._cmd_correlation_stats["metadata_parse_errors"] += 1
                return True

            for meta in parsed_metadata:
                key = f"{meta.table_id:02x}:{meta.device_id:02x}"
                if key not in staged:
                    added += 1
                staged[key] = meta
            if added:
                self._c._cmd_correlation_stats["metadata_entries_staged"] += added
            return True

        return True

    async def connect(self) -> None:
        """Internal connect routine with retry logic."""
        if self._c.is_ethernet_gateway:
            await self._ids_runtime.connect()
            return

        max_attempts = 3
        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                await self._c._try_connect(attempt)
                return
            except Exception as exc:
                last_exc = exc
                _LOGGER.warning(
                    "Connection attempt %d/%d failed: %s",
                    attempt,
                    max_attempts,
                    exc,
                )
                if self._c._client:
                    try:
                        await self._c._client.disconnect()
                    except Exception:
                        pass
                    self._c._client = None
                self._c._connected = False
                self._c._authenticated = False

                if attempt < max_attempts:
                    delay = 3 * attempt
                    _LOGGER.info("Retrying in %ds...", delay)
                    await asyncio.sleep(delay)

        assert last_exc is not None

        if self._c.is_pin_gateway and self._c._pin_already_bonded:
            _LOGGER.warning(
                "PIN gateway %s: BlueZ bond present but all connection attempts failed "
                "- removing stale bond and retrying with fresh PIN pairing",
                self._c.address,
            )
            removed = await remove_bond(self._c.address)
            if removed:
                _LOGGER.info(
                    "Stale bond removed for %s - attempting fresh PIN pairing",
                    self._c.address,
                )
                self._c._pin_dbus_succeeded = False
                self._c._pin_already_bonded = False
                try:
                    await self._c._try_connect(max_attempts + 1)
                    return
                except Exception as stale_exc:
                    last_exc = stale_exc
                    _LOGGER.warning(
                        "Re-pair attempt after stale bond removal failed for %s: %s",
                        self._c.address,
                        stale_exc,
                    )

        if self._c.is_pin_gateway and not self._c._pin_dbus_succeeded:
            _LOGGER.warning(
                "PIN gateway %s: D-Bus bonding did not succeed - skipping "
                "direct adapter fallback. Ensure the gateway PIN is correct "
                "and the device is powered on and in pairing mode.",
                self._c.address,
            )
            raise last_exc

        _LOGGER.warning(
            "All %d HA-routed connection attempts failed for %s; "
            "trying direct HCI adapter fallback",
            max_attempts,
            self._c.address,
        )
        for adapter in ("hci0", "hci1", "hci2", "hci3"):
            _LOGGER.info("Direct BLE connect to %s via %s", self._c.address, adapter)
            try:
                await self._c._try_connect_direct(adapter)
                _LOGGER.info(
                    "Direct connect succeeded via %s for %s",
                    adapter,
                    self._c.address,
                )
                return
            except Exception as exc:
                _LOGGER.debug("Direct connect via %s failed: %s", adapter, exc)
                if self._c._client:
                    try:
                        await self._c._client.disconnect()
                    except Exception:
                        pass
                    self._c._client = None
                self._c._connected = False
                self._c._authenticated = False

        raise last_exc
