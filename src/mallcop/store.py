"""Store ABC and JsonlStore implementation.

All event/finding reads and writes go through the Store abstraction.
JsonlStore persists to JSONL files and uses in-memory SQLite for queries.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import sqlite3
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Source values come from connector manifests (trusted config), not raw
# external input.  The regex enforces alphanumeric-plus-hyphen/dot/underscore
# to prevent any path-traversal character (slashes, null bytes, colons, etc.)
# from reaching the filesystem.  The resolve().is_relative_to() check in
# _event_file_path() provides a second safety layer.
_SAFE_SOURCE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$")

import yaml

from mallcop.feedback import FeedbackRecord
from mallcop.sanitize import sanitize_event, sanitize_finding
from mallcop.schemas import (
    Annotation,
    Baseline,
    Checkpoint,
    Event,
    Finding,
    FindingStatus,
    Severity,
)


class Store(ABC):
    @abstractmethod
    def append_events(self, events: list[Event]) -> None:
        """Persist new events."""

    @abstractmethod
    def query_events(
        self,
        source: str | None = None,
        since: datetime | None = None,
        actor: str | None = None,
        limit: int = 1000,
        event_ids: list[str] | None = None,
    ) -> list[Event]:
        """Query events with optional filters."""

    def query_events_by_ids(self, event_ids: list[str]) -> list[Event]:
        """Query events by their IDs directly, bypassing limit constraints."""
        if not event_ids:
            return []
        return self.query_events(event_ids=event_ids, limit=len(event_ids))

    @abstractmethod
    def append_findings(self, findings: list[Finding]) -> None:
        """Persist new findings."""

    @abstractmethod
    def update_finding(self, finding_id: str, **updates: Any) -> None:
        """Update finding status, add annotations."""

    @abstractmethod
    def query_findings(
        self,
        status: str | None = None,
        severity: str | None = None,
        actor: str | None = None,
        detector: str | None = None,
        since: datetime | None = None,
    ) -> list[Finding]:
        """Query findings with optional filters."""

    @abstractmethod
    def get_checkpoint(self, connector: str) -> Checkpoint | None:
        """Get last checkpoint for a connector."""

    @abstractmethod
    def set_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Update connector checkpoint."""

    @abstractmethod
    def get_baseline(self) -> Baseline:
        """Compute or retrieve current baseline."""

    @abstractmethod
    def update_baseline(self, events: list[Event], window_days: int | None = None) -> None:
        """Update baseline with events. If window_days is set, frequency tables
        only count events within that window. Known entities use all events."""

    @abstractmethod
    def append_feedback(self, record: FeedbackRecord) -> None:
        """Persist a feedback record to .mallcop/feedback.jsonl."""

    @abstractmethod
    def query_feedback(
        self,
        actor: str | None = None,
        detector: str | None = None,
    ) -> list[FeedbackRecord]:
        """Query accumulated feedback records with optional filters."""


class JsonlStore(Store):
    """Store implementation backed by JSONL files and in-memory SQLite."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._data_dir = self._root / ".mallcop"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._events_dir = self._data_dir / "events"
        self._findings_path = self._data_dir / "findings.jsonl"
        self._checkpoints_path = self._data_dir / "checkpoints.yaml"
        self._baseline_path = self._data_dir / "baseline.json"

        self._feedback_path = self._data_dir / "feedback.jsonl"

        self._db = sqlite3.connect(":memory:")
        self._init_schema()
        self._load_from_disk()

    def _init_schema(self) -> None:
        cur = self._db.cursor()
        cur.execute("""
            CREATE TABLE events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                severity TEXT NOT NULL,
                metadata TEXT NOT NULL,
                raw TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE findings (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                detector TEXT NOT NULL,
                event_ids TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                annotations TEXT NOT NULL,
                metadata TEXT NOT NULL
            )
        """)
        self._db.commit()

    def _load_from_disk(self) -> None:
        # Load events
        if self._events_dir.exists():
            for jsonl_file in sorted(self._events_dir.glob("*.jsonl")):
                for line_num, line in enumerate(jsonl_file.read_text().strip().split("\n"), 1):
                    if line:
                        try:
                            evt = Event.from_json(line)
                            self._insert_event_to_cache(evt)
                        except Exception:
                            logger.warning("Skipping corrupt event line %d in %s", line_num, jsonl_file.name)

        # Load findings
        if self._findings_path.exists():
            text = self._findings_path.read_text().strip()
            if text:
                for line_num, line in enumerate(text.split("\n"), 1):
                    if line:
                        try:
                            fnd = Finding.from_json(line)
                            self._insert_finding_to_cache(fnd)
                        except Exception:
                            logger.warning("Skipping corrupt finding line %d in findings.jsonl", line_num)

        # Load checkpoints
        self._checkpoints: dict[str, Checkpoint] = {}
        if self._checkpoints_path.exists():
            data = yaml.safe_load(self._checkpoints_path.read_text())
            if data:
                for connector, cp_data in data.items():
                    self._checkpoints[connector] = Checkpoint(
                        connector=connector,
                        value=cp_data["value"],
                        updated_at=datetime.fromisoformat(cp_data["updated_at"]),
                    )

        # Load baseline
        self._baseline: Baseline | None = None
        if self._baseline_path.exists():
            text = self._baseline_path.read_text().strip()
            if text:
                self._baseline = Baseline.from_dict(json.loads(text))

    def _insert_event_to_cache(self, evt: Event) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                evt.id,
                evt.timestamp.isoformat(),
                evt.ingested_at.isoformat(),
                evt.source,
                evt.event_type,
                evt.actor,
                evt.action,
                evt.target,
                evt.severity.value,
                json.dumps(evt.metadata),
                json.dumps(evt.raw),
            ),
        )
        self._db.commit()

    def _insert_finding_to_cache(self, fnd: Finding) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
            (
                fnd.id,
                fnd.timestamp.isoformat(),
                fnd.detector,
                json.dumps(fnd.event_ids),
                fnd.title,
                fnd.severity.value,
                fnd.status.value,
                json.dumps([a.to_dict() for a in fnd.annotations]),
                json.dumps(fnd.metadata),
            ),
        )
        self._db.commit()

    def _event_file_path(self, source: str, timestamp: datetime) -> Path:
        if not _SAFE_SOURCE.match(source):
            raise ValueError(f"Invalid source name: {source!r}")
        month_str = timestamp.strftime("%Y-%m")
        path = self._events_dir / f"{source}-{month_str}.jsonl"
        if not path.resolve().is_relative_to(self._events_dir.resolve()):
            raise ValueError(f"Invalid source name: {source!r}")
        return path

    def append_events(self, events: list[Event]) -> None:
        self._events_dir.mkdir(parents=True, exist_ok=True)
        for evt in events:
            evt = sanitize_event(evt)
            path = self._event_file_path(evt.source, evt.timestamp)
            with open(path, "a") as f:
                f.write(evt.to_json() + "\n")
            self._insert_event_to_cache(evt)

    def query_events(
        self,
        source: str | None = None,
        since: datetime | None = None,
        actor: str | None = None,
        limit: int = 1000,
        event_ids: list[str] | None = None,
    ) -> list[Event]:
        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []

        if event_ids is not None:
            placeholders = ",".join("?" for _ in event_ids)
            query += f" AND id IN ({placeholders})"
            params.extend(event_ids)
        if source is not None:
            query += " AND source = ?"
            params.append(source)
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())
        if actor is not None:
            query += " AND actor = ?"
            params.append(actor)

        query += " ORDER BY timestamp ASC LIMIT ?"
        params.append(limit)

        cur = self._db.execute(query, params)
        results: list[Event] = []
        for row in cur.fetchall():
            results.append(Event(
                id=row[0],
                timestamp=datetime.fromisoformat(row[1]),
                ingested_at=datetime.fromisoformat(row[2]),
                source=row[3],
                event_type=row[4],
                actor=row[5],
                action=row[6],
                target=row[7],
                severity=Severity(row[8]),
                metadata=json.loads(row[9]),
                raw=json.loads(row[10]),
            ))
        return results

    def append_findings(self, findings: list[Finding]) -> None:
        self._findings_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._findings_path, "a") as f:
            for fnd in findings:
                fnd = sanitize_finding(fnd)
                f.write(fnd.to_json() + "\n")
                self._insert_finding_to_cache(fnd)

    def update_finding(self, finding_id: str, **updates: Any) -> None:
        # Update in-memory cache
        if "status" in updates:
            status_val = updates["status"]
            if isinstance(status_val, FindingStatus):
                status_str = status_val.value
            else:
                status_str = status_val
            self._db.execute(
                "UPDATE findings SET status = ? WHERE id = ?",
                (status_str, finding_id),
            )

        if "annotations" in updates:
            # Get current annotations, append new ones
            cur = self._db.execute(
                "SELECT annotations FROM findings WHERE id = ?",
                (finding_id,),
            )
            row = cur.fetchone()
            if row:
                existing = json.loads(row[0])
                new_anns = [a.to_dict() for a in updates["annotations"]]
                existing.extend(new_anns)
                self._db.execute(
                    "UPDATE findings SET annotations = ? WHERE id = ?",
                    (json.dumps(existing), finding_id),
                )

        # Rewrite findings.jsonl from cache before committing.
        # _rewrite_findings reads uncommitted changes from the same connection,
        # so the file is updated atomically first.  If we crash after the file
        # write but before the commit, the next startup reloads the correct
        # state from disk (SQLite is in-memory and lost on restart anyway).
        self._rewrite_findings()
        self._db.commit()

    def _rewrite_findings(self) -> None:
        cur = self._db.execute("SELECT * FROM findings ORDER BY timestamp ASC")
        fd, tmp = tempfile.mkstemp(dir=self._findings_path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                for row in cur.fetchall():
                    fnd = Finding(
                        id=row[0],
                        timestamp=datetime.fromisoformat(row[1]),
                        detector=row[2],
                        event_ids=json.loads(row[3]),
                        title=row[4],
                        severity=Severity(row[5]),
                        status=FindingStatus(row[6]),
                        annotations=[Annotation.from_dict(a) for a in json.loads(row[7])],
                        metadata=json.loads(row[8]),
                    )
                    f.write(fnd.to_json() + "\n")
            os.replace(tmp, self._findings_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def query_findings(
        self,
        status: str | None = None,
        severity: str | None = None,
        actor: str | None = None,
        detector: str | None = None,
        since: datetime | None = None,
    ) -> list[Finding]:
        query = "SELECT * FROM findings WHERE 1=1"
        params: list[Any] = []

        if status is not None:
            query += " AND status = ?"
            params.append(status)
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity)
        if actor is not None:
            query += " AND json_extract(metadata, '$.actor') LIKE ?"
            params.append(f"%{actor}%")
        if detector is not None:
            query += " AND detector = ?"
            params.append(detector)
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())

        query += " ORDER BY timestamp ASC"

        cur = self._db.execute(query, params)
        results: list[Finding] = []
        for row in cur.fetchall():
            results.append(Finding(
                id=row[0],
                timestamp=datetime.fromisoformat(row[1]),
                detector=row[2],
                event_ids=json.loads(row[3]),
                title=row[4],
                severity=Severity(row[5]),
                status=FindingStatus(row[6]),
                annotations=[Annotation.from_dict(a) for a in json.loads(row[7])],
                metadata=json.loads(row[8]),
            ))
        return results

    def get_checkpoint(self, connector: str) -> Checkpoint | None:
        return self._checkpoints.get(connector)

    def set_checkpoint(self, checkpoint: Checkpoint) -> None:
        self._checkpoints[checkpoint.connector] = checkpoint
        self._write_checkpoints()

    def _write_checkpoints(self) -> None:
        data: dict[str, Any] = {}
        for connector, cp in self._checkpoints.items():
            data[connector] = {
                "value": cp.value,
                "updated_at": cp.updated_at.isoformat(),
            }
        fd, tmp = tempfile.mkstemp(dir=self._checkpoints_path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                yaml.dump(data, f, default_flow_style=False)
            os.replace(tmp, self._checkpoints_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def get_baseline(self) -> Baseline:
        if self._baseline is not None:
            return self._baseline
        return Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
        )

    def update_baseline(self, events: list[Event], window_days: int | None = None) -> None:
        from datetime import timedelta, timezone as tz

        bl = self.get_baseline()

        # Known entities use ALL events (persist indefinitely)
        known = dict(bl.known_entities)
        # Relationships are recomputed from all events (like frequency tables)
        rels: dict[str, Any] = {}

        actors_set: set[str] = set(known.get("actors", []))
        sources_set: set[str] = set(known.get("sources", []))

        # actor_roles: dict mapping actor -> list of known role keys
        # Reconstruct as dict[str, set[str]] for efficient dedup, then serialize as lists
        _ELEVATION_EVENT_TYPES = {
            "role_assignment",
            "collaborator_added",
            "permission_change",
            "admin_action",
        }
        actor_roles_raw: dict[str, set[str]] = {}
        for actor, roles_list in known.get("actor_roles", {}).items():
            actor_roles_raw[actor] = set(roles_list)

        for evt in events:
            actors_set.add(evt.actor)
            sources_set.add(evt.source)

            # Relationships: "actor:target" -> {count, first_seen, last_seen}
            rel_key = f"{evt.actor}:{evt.target}"
            ts_iso = evt.timestamp.isoformat()
            if rel_key in rels:
                rels[rel_key]["count"] += 1
                if ts_iso < rels[rel_key]["first_seen"]:
                    rels[rel_key]["first_seen"] = ts_iso
                if ts_iso > rels[rel_key]["last_seen"]:
                    rels[rel_key]["last_seen"] = ts_iso
            else:
                rels[rel_key] = {
                    "count": 1,
                    "first_seen": ts_iso,
                    "last_seen": ts_iso,
                }

            # actor_roles: extract role keys from elevation event types
            if evt.event_type in _ELEVATION_EVENT_TYPES:
                role_key = (
                    evt.metadata.get("role_name")
                    or evt.metadata.get("permission_level")
                    or evt.event_type
                )
                if evt.actor not in actor_roles_raw:
                    actor_roles_raw[evt.actor] = set()
                actor_roles_raw[evt.actor].add(role_key)

        known["actors"] = sorted(actors_set)
        known["sources"] = sorted(sources_set)
        known["actor_roles"] = {
            actor: sorted(roles) for actor, roles in actor_roles_raw.items()
        }

        # Frequency tables: recompute from ALL stored events within window,
        # not just the events passed as argument. This ensures freq tables
        # are complete even if the caller passes a subset.
        if window_days is not None:
            cutoff = datetime.now(tz.utc) - timedelta(days=window_days)
            freq_events = self.query_events(since=cutoff, limit=100_000)
        else:
            freq_events = self.query_events(limit=100_000)

        from mallcop.baseline import hour_bucket as _hour_bucket

        freq: dict[str, int] = {}
        for evt in freq_events:
            # Aggregate key (no time dimension) — used by volume-anomaly etc.
            key = f"{evt.source}:{evt.event_type}:{evt.actor}"
            freq[key] = freq.get(key, 0) + 1
            # Time-dimensioned key — used by unusual-timing detector
            time_key = (
                f"{evt.source}:{evt.event_type}:{evt.actor}"
                f":{evt.timestamp.weekday()}:{_hour_bucket(evt.timestamp.hour)}"
            )
            freq[time_key] = freq.get(time_key, 0) + 1
            # Action-level key: source:event_type:actor:action:target_prefix
            # Makes baseline camping more expensive: attacker must pre-seed every
            # specific action on every specific target, not just actor:event_type.
            target_prefix = "/".join(evt.target.split("/")[:3])
            action_key = f"{evt.source}:{evt.event_type}:{evt.actor}:{evt.action}:{target_prefix}"
            freq[action_key] = freq.get(action_key, 0) + 1

        self._baseline = Baseline(
            frequency_tables=freq,
            known_entities=known,
            relationships=rels,
        )

        # Persist atomically
        fd, tmp = tempfile.mkstemp(dir=self._baseline_path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self._baseline.to_dict(), f)
            os.replace(tmp, self._baseline_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def append_feedback(self, record: FeedbackRecord) -> None:
        """Persist a feedback record to .mallcop/feedback.jsonl."""
        self._feedback_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._feedback_path, "a") as f:
            f.write(record.to_json() + "\n")

    def query_feedback(
        self,
        actor: str | None = None,
        detector: str | None = None,
    ) -> list[FeedbackRecord]:
        """Query feedback records from .mallcop/feedback.jsonl with optional filters."""
        if not self._feedback_path.exists():
            return []
        text = self._feedback_path.read_text().strip()
        if not text:
            return []
        results: list[FeedbackRecord] = []
        for line in text.splitlines():
            if not line:
                continue
            rec = FeedbackRecord.from_json(line)
            if detector is not None and rec.detector != detector:
                continue
            # actor filter: check if actor appears in events or baseline_snapshot
            if actor is not None:
                actors_in_events = {e.get("actor", "") for e in rec.events}
                bl_actors = rec.baseline_snapshot.get("actors", [])
                if isinstance(bl_actors, list):
                    actors_in_baseline = set(bl_actors)
                else:
                    actors_in_baseline = set()
                if actor not in actors_in_events and actor not in actors_in_baseline:
                    continue
            results.append(rec)
        return results
