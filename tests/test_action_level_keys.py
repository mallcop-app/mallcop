"""Tests for action-level frequency keys in baseline.

Bead: mallcop-9hf5.13

Action-level keys: source:event_type:actor:action:target_prefix
target_prefix = first 3 segments of target path (generic split on '/')

These keys make baseline camping more expensive: attacker must pre-seed
every specific action on every specific target, not just actor:event_type.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mallcop.schemas import Event, Severity


def _make_event(
    source: str = "azure",
    event_type: str = "resource_access",
    actor: str = "admin-user",
    action: str = "read",
    target: str = "sub-xxx/resourceGroups/atom-rg/providers/Microsoft.Compute/virtualMachines/vm1",
    daysago: int = 0,
) -> Event:
    now = datetime.now(timezone.utc)
    return Event(
        id=f"evt_{actor}_{action}_{target.replace('/', '_')}",
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        timestamp=now,
        ingested_at=now,
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


# ---------------------------------------------------------------------------
# target_prefix extraction
# ---------------------------------------------------------------------------

class TestTargetPrefix:
    """The target_prefix is the first 3 segments of target path split on '/'."""

    def _prefix(self, target: str) -> str:
        """Helper: replicate the target_prefix logic."""
        parts = target.split("/")
        return "/".join(parts[:3])

    def test_azure_path_3_segments(self):
        target = "sub-xxx/resourceGroups/atom-rg/providers/Microsoft.Compute/vms/vm1"
        assert self._prefix(target) == "sub-xxx/resourceGroups/atom-rg"

    def test_github_path(self):
        target = "mallcop-app/mallcop/pulls/42"
        assert self._prefix(target) == "mallcop-app/mallcop/pulls"

    def test_short_path_one_segment(self):
        target = "global"
        assert self._prefix(target) == "global"

    def test_short_path_two_segments(self):
        target = "org/repo"
        assert self._prefix(target) == "org/repo"

    def test_empty_target(self):
        assert self._prefix("") == ""


# ---------------------------------------------------------------------------
# update_baseline produces action-level keys
# ---------------------------------------------------------------------------

class TestActionLevelKeys:
    def _make_store(self, tmp_path):
        from mallcop.store import JsonlStore
        return JsonlStore(tmp_path)

    def _action_keys(self, bl, source="azure", event_type="resource_access", action=None, target_prefix=None):
        """Filter frequency_tables for action-level keys (5 colon-separated parts from source:event_type).

        Keys are sanitized: values are wrapped in [USER_DATA_BEGIN/END]. We match by checking
        that the segment CONTAINS the bare value (since sanitization wraps, not replaces).
        """
        result = {}
        for k, v in bl.frequency_tables.items():
            parts = k.split(":")
            # action-level keys have 5+ parts: source, event_type, actor, action, target...
            # time keys: parts[3] is an integer weekday
            if len(parts) < 5:
                continue
            if parts[0] != source or parts[1] != event_type:
                continue
            # Distinguish action keys from time keys: time keys have integer weekday at parts[3]
            raw_action_segment = parts[3]
            try:
                int(raw_action_segment)
                continue  # time key, skip
            except ValueError:
                pass  # action key
            # Check action segment contains the bare action value (sanitization wraps, not replaces)
            if action is not None and action not in raw_action_segment:
                continue
            # Check target_prefix appears somewhere after the action segment
            if target_prefix is not None and target_prefix not in k:
                continue
            result[k] = v
        return result

    def test_action_level_key_present(self, tmp_path):
        store = self._make_store(tmp_path)
        evt = _make_event(
            source="azure",
            event_type="resource_access",
            actor="admin-user",
            action="read",
            target="sub-xxx/resourceGroups/atom-rg/providers/Microsoft.Compute/vms/vm1",
        )
        store.append_events([evt])
        store.update_baseline(store.query_events())
        bl = store.get_baseline()

        action_keys = self._action_keys(bl, action="read", target_prefix="sub-xxx/resourceGroups/atom-rg")
        assert len(action_keys) == 1

    def test_old_3part_key_still_present(self, tmp_path):
        store = self._make_store(tmp_path)
        evt = _make_event()
        store.append_events([evt])
        store.update_baseline(store.query_events())
        bl = store.get_baseline()

        # 3-part keys: source:event_type:actor (exactly 3 colon-separated parts)
        three_part_keys = [k for k in bl.frequency_tables if k.count(":") == 2]
        assert len(three_part_keys) >= 1

    def test_old_5part_time_key_still_present(self, tmp_path):
        store = self._make_store(tmp_path)
        evt = _make_event()
        store.append_events([evt])
        store.update_baseline(store.query_events())
        bl = store.get_baseline()

        # Time keys: 5-part where 4th part is integer weekday
        time_keys = []
        for k in bl.frequency_tables:
            parts = k.split(":")
            if len(parts) == 5:
                try:
                    int(parts[3])
                    time_keys.append(k)
                except ValueError:
                    pass
        assert len(time_keys) >= 1

    def test_action_level_count_increments(self, tmp_path):
        store = self._make_store(tmp_path)
        evt1 = _make_event(action="read", target="sub-xxx/resourceGroups/atom-rg/vm1")
        evt2 = _make_event(action="read", target="sub-xxx/resourceGroups/atom-rg/vm2")
        store.append_events([evt1, evt2])
        store.update_baseline(store.query_events())
        bl = store.get_baseline()

        action_keys = self._action_keys(bl, action="read", target_prefix="sub-xxx/resourceGroups/atom-rg")
        assert len(action_keys) == 1
        count = list(action_keys.values())[0]
        assert count == 2

    def test_different_actions_get_different_keys(self, tmp_path):
        store = self._make_store(tmp_path)
        evt_read = _make_event(action="read", target="sub-xxx/resourceGroups/atom-rg/vm1")
        evt_write = _make_event(action="write", target="sub-xxx/resourceGroups/atom-rg/vm1")
        store.append_events([evt_read, evt_write])
        store.update_baseline(store.query_events())
        bl = store.get_baseline()

        read_keys = self._action_keys(bl, action="read")
        write_keys = self._action_keys(bl, action="write")
        assert len(read_keys) >= 1
        assert len(write_keys) >= 1

    def test_different_targets_get_different_keys(self, tmp_path):
        store = self._make_store(tmp_path)
        evt1 = _make_event(action="read", target="sub-xxx/resourceGroups/atom-rg/vm1")
        evt2 = _make_event(action="read", target="sub-xxx/resourceGroups/other-rg/vm1")
        store.append_events([evt1, evt2])
        store.update_baseline(store.query_events())
        bl = store.get_baseline()

        atom_keys = self._action_keys(bl, action="read", target_prefix="sub-xxx/resourceGroups/atom-rg")
        other_keys = self._action_keys(bl, action="read", target_prefix="sub-xxx/resourceGroups/other-rg")
        assert len(atom_keys) >= 1
        assert len(other_keys) >= 1

    def test_event_with_empty_action_uses_empty_string(self, tmp_path):
        """Events with empty action field produce a key with empty action segment."""
        store = self._make_store(tmp_path)
        now = datetime.now(timezone.utc)
        evt = Event(
            id="evt_no_action",
            source="azure",
            event_type="resource_access",
            actor="admin-user",
            action="",  # empty action
            target="sub-xxx/resourceGroups/atom-rg/vm1",
            timestamp=now,
            ingested_at=now,
            severity=Severity.INFO,
            metadata={},
            raw={},
        )
        store.append_events([evt])
        store.update_baseline(store.query_events())
        bl = store.get_baseline()

        # Should have an action-level key with empty action (and time-based keys)
        # Key pattern: azure:resource_access:ACTOR::target_prefix (action segment empty)
        action_keys = self._action_keys(bl, action="")
        assert len(action_keys) >= 1

    def test_short_target_uses_available_segments(self, tmp_path):
        store = self._make_store(tmp_path)
        evt = _make_event(action="delete", target="global")
        store.append_events([evt])
        store.update_baseline(store.query_events())
        bl = store.get_baseline()

        # target_prefix = "global" (single segment), key ends with :delete:global
        action_keys = self._action_keys(bl, action="delete", target_prefix="global")
        assert len(action_keys) >= 1


# ---------------------------------------------------------------------------
# check-baseline returns action-level entries
# ---------------------------------------------------------------------------

class TestCheckBaselineActionKeys:
    def test_check_baseline_includes_action_level_keys(self, tmp_path):
        """check_baseline actor_freq should include action-level keys when queried with sanitized actor."""
        from mallcop.store import JsonlStore
        from mallcop.tools.baseline import check_baseline
        from mallcop.tools import ToolContext
        from mallcop.sanitize import sanitize_field

        store = JsonlStore(tmp_path)
        evt = _make_event(
            actor="admin-user",
            action="read",
            target="sub-xxx/resourceGroups/atom-rg/vm1",
        )
        store.append_events([evt])
        store.update_baseline(store.query_events())

        # At runtime, actor is sanitized — pass the sanitized form as check_baseline receives it
        sanitized_actor = sanitize_field("admin-user")
        ctx = ToolContext(store=store, connectors={}, config=None)
        result = check_baseline(ctx, actor=sanitized_actor)

        # Should include action-level keys (keys with 5+ segments where 4th is not int weekday)
        # Keys are sanitized; check that at least one key has more than 4 colon-separated parts
        # and the 4th part is not an integer (distinguishes action keys from time keys)
        action_freq_keys = []
        for k in result["frequency"]:
            parts = k.split(":")
            if len(parts) >= 5:
                try:
                    int(parts[3])
                except ValueError:
                    action_freq_keys.append(k)
        assert len(action_freq_keys) >= 1, f"No action-level keys in frequency: {result['frequency']}"

    def test_check_baseline_does_not_cross_actors(self, tmp_path):
        """Action-level keys for other actors should not appear in actor's freq response."""
        from mallcop.store import JsonlStore
        from mallcop.tools.baseline import check_baseline
        from mallcop.tools import ToolContext
        from mallcop.sanitize import sanitize_field

        store = JsonlStore(tmp_path)
        evt_admin = _make_event(actor="admin-user", action="read", target="sub-xxx/resourceGroups/atom-rg/vm1")
        evt_other = _make_event(actor="other-user", action="read", target="sub-xxx/resourceGroups/atom-rg/vm1")
        store.append_events([evt_admin, evt_other])
        store.update_baseline(store.query_events())

        sanitized_admin = sanitize_field("admin-user")
        ctx = ToolContext(store=store, connectors={}, config=None)
        result = check_baseline(ctx, actor=sanitized_admin)

        # other-user's sanitized form should not appear in the returned keys
        sanitized_other = sanitize_field("other-user")
        assert not any(sanitized_other in k for k in result["frequency"])
