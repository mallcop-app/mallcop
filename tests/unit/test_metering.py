"""Tests for services/inference/metering.py: token usage metering."""

from __future__ import annotations

import time

import pytest

from services.inference.metering import Meter


class TestMeterRecordAndQuery:
    """Meter records usage and queries it back."""

    def test_record_and_get_usage(self, tmp_path) -> None:
        db_path = str(tmp_path / "test.db")
        meter = Meter(db_path)
        try:
            meter.record("acct-1", "haiku", input_tokens=100, output_tokens=50)
            meter.record("acct-1", "haiku", input_tokens=200, output_tokens=100)

            usage = meter.get_usage("acct-1")
            assert usage["input_tokens"] == 300
            assert usage["output_tokens"] == 150
            assert usage["total_tokens"] == 450
            assert usage["requests"] == 2
        finally:
            meter.close()

    def test_get_usage_empty_account(self, tmp_path) -> None:
        db_path = str(tmp_path / "test.db")
        meter = Meter(db_path)
        try:
            usage = meter.get_usage("acct-nonexistent")
            assert usage["input_tokens"] == 0
            assert usage["output_tokens"] == 0
            assert usage["total_tokens"] == 0
            assert usage["requests"] == 0
        finally:
            meter.close()

    def test_accounts_are_isolated(self, tmp_path) -> None:
        db_path = str(tmp_path / "test.db")
        meter = Meter(db_path)
        try:
            meter.record("acct-1", "haiku", input_tokens=100, output_tokens=50)
            meter.record("acct-2", "sonnet", input_tokens=500, output_tokens=200)

            usage1 = meter.get_usage("acct-1")
            usage2 = meter.get_usage("acct-2")

            assert usage1["total_tokens"] == 150
            assert usage2["total_tokens"] == 700
        finally:
            meter.close()


class TestMeterTimeBounded:
    """Time-bounded usage queries."""

    def test_since_filter(self, tmp_path) -> None:
        db_path = str(tmp_path / "test.db")
        meter = Meter(db_path)
        try:
            # Record some old usage by inserting directly
            old_time = time.time() - 86400 * 2  # 2 days ago
            meter._conn.execute(
                "INSERT INTO usage (account_id, timestamp, model, input_tokens, output_tokens, total_tokens) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("acct-1", old_time, "haiku", 1000, 500, 1500),
            )
            meter._conn.commit()

            # Record recent usage
            meter.record("acct-1", "haiku", input_tokens=100, output_tokens=50)

            # Query all time
            all_usage = meter.get_usage("acct-1")
            assert all_usage["total_tokens"] == 1650

            # Query last 24 hours
            recent_usage = meter.get_usage("acct-1", since=time.time() - 86400)
            assert recent_usage["total_tokens"] == 150
            assert recent_usage["requests"] == 1
        finally:
            meter.close()

    def test_since_none_returns_all(self, tmp_path) -> None:
        db_path = str(tmp_path / "test.db")
        meter = Meter(db_path)
        try:
            meter.record("acct-1", "haiku", input_tokens=100, output_tokens=50)
            usage = meter.get_usage("acct-1", since=None)
            assert usage["total_tokens"] == 150
        finally:
            meter.close()


class TestMeterConcurrency:
    """Concurrent writes to the meter."""

    def test_concurrent_records_are_all_counted(self, tmp_path) -> None:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        db_path = str(tmp_path / "test.db")
        meter = Meter(db_path)
        try:
            num_threads = 8
            records_per_thread = 50

            def writer(thread_id: int) -> int:
                # Each thread creates its own connection to avoid SQLite threading issues
                local_meter = Meter(db_path)
                try:
                    for _ in range(records_per_thread):
                        local_meter.record(
                            "acct-concurrent",
                            f"model-{thread_id}",
                            input_tokens=10,
                            output_tokens=5,
                        )
                    return records_per_thread
                finally:
                    local_meter.close()

            with ThreadPoolExecutor(max_workers=num_threads) as pool:
                futures = [pool.submit(writer, i) for i in range(num_threads)]
                total_written = sum(f.result() for f in as_completed(futures))

            assert total_written == num_threads * records_per_thread

            # Re-read with a fresh connection to see all committed data
            check_meter = Meter(db_path)
            try:
                usage = check_meter.get_usage("acct-concurrent")
                assert usage["requests"] == num_threads * records_per_thread
                assert usage["input_tokens"] == num_threads * records_per_thread * 10
                assert usage["output_tokens"] == num_threads * records_per_thread * 5
                assert usage["total_tokens"] == num_threads * records_per_thread * 15
            finally:
                check_meter.close()
        finally:
            meter.close()

    def test_concurrent_mixed_accounts(self, tmp_path) -> None:
        """Concurrent writes to different accounts stay isolated."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        db_path = str(tmp_path / "test.db")

        def writer(acct: str, count: int, tokens: int) -> None:
            m = Meter(db_path)
            try:
                for _ in range(count):
                    m.record(acct, "haiku", input_tokens=tokens, output_tokens=tokens)
            finally:
                m.close()

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(writer, "acct-a", 20, 10),
                pool.submit(writer, "acct-b", 30, 20),
                pool.submit(writer, "acct-a", 20, 10),
                pool.submit(writer, "acct-b", 30, 20),
            ]
            for f in as_completed(futures):
                f.result()  # raise if any failed

        check = Meter(db_path)
        try:
            a_usage = check.get_usage("acct-a")
            b_usage = check.get_usage("acct-b")
            assert a_usage["requests"] == 40
            assert a_usage["input_tokens"] == 400
            assert b_usage["requests"] == 60
            assert b_usage["input_tokens"] == 1200
        finally:
            check.close()


class TestMeterMultipleModels:
    """Usage tracking across different models."""

    def test_different_models_aggregated(self, tmp_path) -> None:
        db_path = str(tmp_path / "test.db")
        meter = Meter(db_path)
        try:
            meter.record("acct-1", "haiku", input_tokens=100, output_tokens=50)
            meter.record("acct-1", "sonnet", input_tokens=500, output_tokens=200)

            usage = meter.get_usage("acct-1")
            assert usage["input_tokens"] == 600
            assert usage["output_tokens"] == 250
            assert usage["total_tokens"] == 850
            assert usage["requests"] == 2
        finally:
            meter.close()
