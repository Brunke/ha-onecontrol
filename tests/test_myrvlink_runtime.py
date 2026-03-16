"""Runtime-focused tests for MyRvLink metadata sequencing behavior."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from custom_components.ha_onecontrol.protocol.events import DeviceMetadata
from custom_components.ha_onecontrol.protocol.events import GatewayInformation
from custom_components.ha_onecontrol.protocol.events import RelayStatus
from custom_components.ha_onecontrol.protocol.events import TankLevel
from custom_components.ha_onecontrol.runtime.ids_can_runtime import IdsCanRuntime
from custom_components.ha_onecontrol.runtime.myrvlink_runtime import MyRvLinkRuntime


class _DummyCmd:
    def build_get_devices(self, table_id: int) -> bytes:
        return bytes([0x34, 0x12, table_id & 0xFF])

    def build_get_devices_metadata(self, table_id: int) -> bytes:
        return bytes([0x78, 0x56, table_id & 0xFF])


class _DummyHass:
    def __init__(self) -> None:
        self.scheduled = []

    def async_create_task(self, coro):
        self.scheduled.append(coro)
        try:
            coro.close()
        except Exception:
            pass
        return None


def _base_state() -> SimpleNamespace:
    pending_get = {}
    pending_meta = {}
    sent_commands = []

    async def _send_command(raw: bytes) -> None:
        sent_commands.append(raw)

    def _record_pending_get_devices_cmd(cmd_id: int, table_id: int) -> None:
        pending_get[cmd_id] = table_id

    def _record_pending_metadata_cmd(cmd_id: int, table_id: int) -> None:
        pending_meta[cmd_id] = table_id

    return SimpleNamespace(
        address="AA:BB:CC:DD:EE:FF",
        is_ethernet_gateway=False,
        _supports_metadata_requests=True,
        _connected=True,
        _authenticated=True,
        _initial_get_devices_sent=False,
        _select_get_devices_table_id=lambda: 0x03,
        _cmd=_DummyCmd(),
        async_send_command=_send_command,
        _record_pending_get_devices_cmd=_record_pending_get_devices_cmd,
        _record_pending_metadata_cmd=_record_pending_metadata_cmd,
        _pending_get_devices_cmdids=pending_get,
        _pending_get_devices_sent_at={},
        _pending_metadata_cmdids=pending_meta,
        _pending_metadata_sent_at={},
        _pending_metadata_entries={},
        _metadata_requested_tables=set(),
        _metadata_loaded_tables=set(),
        _metadata_rejected_tables=set(),
        _metadata_raw={},
        device_names={},
        _get_devices_loaded_tables=set(),
        _metadata_retry_counts={},
        _cmd_correlation_stats={
            "metadata_waiting_get_devices": 0,
            "get_devices_identity_rows": 0,
            "metadata_success_multi_discarded_unknown": 0,
            "metadata_success_multi_accepted": 0,
            "metadata_entries_staged": 0,
            "metadata_parse_errors": 0,
            "metadata_commit_success": 0,
            "metadata_commit_crc_mismatch": 0,
            "metadata_commit_count_mismatch": 0,
            "metadata_retry_scheduled": 0,
            "command_error_unknown": 0,
            "get_devices_rejected": 0,
            "get_devices_completed": 0,
            "pending_cmdid_pruned": 0,
            "pending_get_devices_peak": 0,
            "unknown_cmdids_pruned": 0,
        },
        _device_identities={},
        _unknown_command_counts={},
        _process_metadata=lambda *_: None,
        _apply_external_name=lambda *_: None,
        _bump_unknown_cmd_count=lambda _: 1,
        _last_metadata_crc=None,
        gateway_info=None,
        hass=_DummyHass(),
        _try_connect=lambda *_: None,
        _try_connect_direct=lambda *_: None,
        _client=None,
        _pin_already_bonded=False,
        _pin_dbus_succeeded=False,
        is_pin_gateway=False,
    )


def test_myrvlink_runtime_do_send_initial_get_devices_records_and_sends() -> None:
    """Initial GetDevices should set pending cmdId and mark bootstrap sent."""
    state = _base_state()
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]

    asyncio.run(runtime.do_send_initial_get_devices())

    assert state._initial_get_devices_sent is True
    assert state._pending_get_devices_cmdids.get(0x1234) == 0x03


def test_myrvlink_runtime_request_metadata_after_delay_defers_until_getdevices() -> None:
    """Metadata delay path should defer and bump waiting counter when table not loaded."""
    state = _base_state()
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]

    original_sleep = asyncio.sleep

    async def _sleep(_: float) -> None:
        return

    asyncio.sleep = _sleep
    try:
        asyncio.run(runtime.request_metadata_after_delay(0x03))
    finally:
        asyncio.sleep = original_sleep

    assert state._cmd_correlation_stats["metadata_waiting_get_devices"] == 1
    assert 0x5678 not in state._pending_metadata_cmdids


def test_myrvlink_runtime_send_metadata_request_tracks_pending() -> None:
    """Metadata request should register pending cmdId and requested table state."""
    state = _base_state()
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]

    asyncio.run(runtime.send_metadata_request(0x05))

    assert state._pending_metadata_cmdids.get(0x5678) == 0x05
    assert 0x05 in state._metadata_requested_tables


def test_myrvlink_runtime_handle_command_frame_get_devices_successmulti() -> None:
    """Standard 0x02 command frame should decode GetDevices identities."""
    state = _base_state()
    state._pending_get_devices_cmdids = {0x1234: 0x03}
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]

    frame = bytes(
        [
            0x02,
            0x34,
            0x12,
            0x01,
            0x03,
            0x00,
            0x01,
            0x01,
            0x0A,
            0x14,
            0x01,
            0x00,
            0x67,
            0x00,
            0x00,
            0x00,
            0x08,
            0xE9,
            0xBC,
        ]
    )

    consumed = runtime.handle_command_frame(frame)

    assert consumed is True
    assert state._cmd_correlation_stats["get_devices_identity_rows"] == 1
    assert "03:00" in state._device_identities


def test_myrvlink_runtime_gateway_info_crc_change_invalidates_cached_metadata() -> None:
    """GatewayInfo with changed metadata CRC should invalidate cached table metadata."""
    state = _base_state()
    state._last_metadata_crc = 0x11223344
    state._metadata_loaded_tables = {0x03}
    state._metadata_requested_tables = {0x03}
    state._metadata_rejected_tables = {0x03}
    state._metadata_raw = {
        "03:10": object(),
        "03:11": object(),
        "04:01": object(),
    }
    state.device_names = {
        "03:10": "A",
        "03:11": "B",
        "04:01": "C",
    }
    state._supports_metadata_requests = False

    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]
    event = GatewayInformation(
        table_id=0x03,
        device_count=2,
        device_table_crc=0,
        device_metadata_table_crc=0x55667788,
    )

    runtime.handle_gateway_information(event)

    assert state._last_metadata_crc is None
    assert 0x03 not in state._metadata_loaded_tables
    assert 0x03 not in state._metadata_requested_tables
    assert 0x03 not in state._metadata_rejected_tables
    assert "03:10" not in state._metadata_raw
    assert "03:11" not in state._metadata_raw
    assert "04:01" in state._metadata_raw
    assert state.gateway_info == event


def test_myrvlink_runtime_gateway_info_waits_for_get_devices_before_metadata() -> None:
    """GatewayInfo should increment waiting counter when GetDevices not yet complete."""
    state = _base_state()
    state._supports_metadata_requests = True
    state._get_devices_loaded_tables = set()
    state._initial_get_devices_sent = True
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]
    event = GatewayInformation(
        table_id=0x05,
        device_count=1,
        device_table_crc=0,
        device_metadata_table_crc=0,
    )

    runtime.handle_gateway_information(event)

    assert state._cmd_correlation_stats["metadata_waiting_get_devices"] == 1


def test_myrvlink_runtime_process_metadata_sets_name_and_crc() -> None:
    """Metadata rows should update name cache and primary-table CRC tracking."""
    state = _base_state()
    state.gateway_info = GatewayInformation(
        table_id=0x03,
        device_count=1,
        device_table_crc=0,
        device_metadata_table_crc=0xABCDEF01,
    )
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]

    runtime.process_metadata(
        DeviceMetadata(table_id=0x03, device_id=0x10, function_name=1, function_instance=0)
    )

    assert "03:10" in state._metadata_raw
    assert "03:10" in state.device_names
    assert state._last_metadata_crc == 0xABCDEF01


def test_myrvlink_runtime_reset_protocol_tracking_state_clears_pending_maps() -> None:
    """Disconnect reset should clear pending metadata/get-devices tracking structures."""
    state = _base_state()
    state._metadata_requested_tables = {0x03}
    state._metadata_loaded_tables = {0x03}
    state._metadata_rejected_tables = {0x05}
    state._metadata_retry_counts = {0x05: 2}
    state._pending_metadata_cmdids = {0x1111: 0x03}
    state._pending_metadata_sent_at = {0x1111: 1.0}
    state._pending_metadata_entries = {0x1111: {"03:10": object()}}
    state._pending_get_devices_cmdids = {0x2222: 0x03}
    state._pending_get_devices_sent_at = {0x2222: 1.0}
    state._get_devices_loaded_tables = {0x03}
    state._unknown_command_counts = {0x3333: 4}
    state._initial_get_devices_sent = True

    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]
    runtime.reset_protocol_tracking_state()

    assert not state._metadata_requested_tables
    assert not state._metadata_loaded_tables
    assert not state._metadata_rejected_tables
    assert not state._metadata_retry_counts
    assert not state._pending_metadata_cmdids
    assert not state._pending_metadata_sent_at
    assert not state._pending_metadata_entries
    assert not state._pending_get_devices_cmdids
    assert not state._pending_get_devices_sent_at
    assert not state._get_devices_loaded_tables
    assert not state._unknown_command_counts
    assert state._initial_get_devices_sent is False


def test_myrvlink_runtime_handle_metadata_for_event_routes_table_events() -> None:
    """Table-scoped status events should route to ensure_metadata_for_table."""
    state = _base_state()
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]
    requested: list[int] = []

    runtime.ensure_metadata_for_table = requested.append  # type: ignore[method-assign]
    runtime.handle_metadata_for_event(RelayStatus(table_id=0x05, device_id=0x22, is_on=True))

    assert requested == [0x05]


def test_myrvlink_runtime_handle_metadata_for_event_routes_list_items() -> None:
    """List payloads should recurse into tank status and metadata rows."""
    state = _base_state()
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]
    requested: list[int] = []
    processed: list[tuple[int, int]] = []

    runtime.ensure_metadata_for_table = requested.append  # type: ignore[method-assign]
    runtime.process_metadata = (  # type: ignore[method-assign]
        lambda meta: processed.append((meta.table_id, meta.device_id))
    )

    runtime.handle_metadata_for_event(
        [
            TankLevel(table_id=0x03, device_id=0x10, level=66),
            DeviceMetadata(table_id=0x03, device_id=0x10, function_name=1, function_instance=0),
        ]
    )

    assert requested == [0x03]
    assert processed == [(0x03, 0x10)]


def test_myrvlink_runtime_record_pending_get_devices_prunes_to_limit() -> None:
    """GetDevices cmd tracking should prune oldest entries when max is exceeded."""
    state = _base_state()
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]

    runtime.record_pending_get_devices_cmd(0x1001, 0x03, max_pending=1)
    runtime.record_pending_get_devices_cmd(0x1002, 0x04, max_pending=1)

    assert state._pending_get_devices_cmdids == {0x1002: 0x04}
    assert state._cmd_correlation_stats["pending_cmdid_pruned"] >= 1
    assert state._cmd_correlation_stats["pending_get_devices_peak"] == 1


def test_myrvlink_runtime_prune_pending_command_state_drops_stale_entries(monkeypatch) -> None:
    """Stale pending cmd IDs should be removed from both get-devices and metadata maps."""
    state = _base_state()
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]

    state._pending_get_devices_cmdids = {0x2001: 0x03}
    state._pending_get_devices_sent_at = {0x2001: 10.0}
    state._pending_metadata_cmdids = {0x2002: 0x05}
    state._pending_metadata_sent_at = {0x2002: 10.0}
    state._pending_metadata_entries = {0x2002: {"05:10": object()}}

    monkeypatch.setattr("custom_components.ha_onecontrol.runtime.myrvlink_runtime.time.monotonic", lambda: 100.0)

    runtime.prune_pending_command_state(stale_timeout_s=30.0)

    assert not state._pending_get_devices_cmdids
    assert not state._pending_get_devices_sent_at
    assert not state._pending_metadata_cmdids
    assert not state._pending_metadata_sent_at
    assert not state._pending_metadata_entries
    assert state._cmd_correlation_stats["pending_cmdid_pruned"] >= 2


def test_myrvlink_runtime_bump_unknown_cmd_count_prunes_when_bounded() -> None:
    """Unknown cmdId tracking should prune oldest entries past the configured bound."""
    state = _base_state()
    runtime = MyRvLinkRuntime(state, IdsCanRuntime(state))  # type: ignore[arg-type]

    assert runtime.bump_unknown_cmd_count(0x3001, max_unknown=1) == 1
    assert runtime.bump_unknown_cmd_count(0x3002, max_unknown=1) == 1

    assert state._unknown_command_counts == {0x3002: 1}
    assert state._cmd_correlation_stats["unknown_cmdids_pruned"] == 1
