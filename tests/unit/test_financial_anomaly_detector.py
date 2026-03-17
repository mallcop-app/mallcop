"""Tests for financial-anomaly detector."""

from datetime import datetime, timezone

import pytest

from mallcop.detectors.financial_anomalies.detector import FinancialAnomalyDetector
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str = "evt_001",
    source: str = "bank-api",
    timestamp: datetime | None = None,
    actor: str = "finance@example.com",
    event_type: str = "transfer",
    action: str = "send",
    target: str = "acct_new_recipient",
    metadata: dict | None = None,
) -> Event:
    return Event(
        id=id,
        timestamp=timestamp or _utcnow(),
        ingested_at=_utcnow(),
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=Severity.WARN,
        metadata=metadata or {},
        raw={},
    )


def _make_baseline(
    recipients: list[str] | None = None,
    amount_maxes: dict[str, float] | None = None,
) -> Baseline:
    known = {}
    if recipients is not None:
        known["recipients"] = recipients
    freq = {}
    if amount_maxes:
        for source, mx in amount_maxes.items():
            freq[f"amount_max:{source}"] = mx
    return Baseline(
        frequency_tables=freq,
        known_entities=known,
        relationships={},
    )


class TestNewRecipientDetection:
    def test_flags_unknown_recipient(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(target="acct_unknown")]
        baseline = _make_baseline(recipients=["acct_known"])

        findings = detector.detect(events, baseline)

        recipient_findings = [f for f in findings if f.metadata.get("type") == "new_recipient"]
        assert len(recipient_findings) == 1
        assert "acct_unknown" in recipient_findings[0].title
        assert recipient_findings[0].severity == Severity.WARN
        assert recipient_findings[0].detector == "financial-anomaly"

    def test_does_not_flag_known_recipient(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(target="acct_known")]
        baseline = _make_baseline(recipients=["acct_known"])

        findings = detector.detect(events, baseline)

        recipient_findings = [f for f in findings if f.metadata.get("type") == "new_recipient"]
        assert len(recipient_findings) == 0

    def test_multiple_events_same_new_recipient_one_finding(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [
            _make_event(id="evt_1", target="acct_new"),
            _make_event(id="evt_2", target="acct_new"),
        ]
        baseline = _make_baseline(recipients=["acct_known"])

        findings = detector.detect(events, baseline)

        recipient_findings = [f for f in findings if f.metadata.get("type") == "new_recipient"]
        assert len(recipient_findings) == 1
        assert set(recipient_findings[0].event_ids) == {"evt_1", "evt_2"}

    def test_multiple_new_recipients_separate_findings(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [
            _make_event(id="evt_1", target="acct_new_a"),
            _make_event(id="evt_2", target="acct_new_b"),
        ]
        baseline = _make_baseline(recipients=["acct_known"])

        findings = detector.detect(events, baseline)

        recipient_findings = [f for f in findings if f.metadata.get("type") == "new_recipient"]
        assert len(recipient_findings) == 2

    def test_empty_recipients_baseline_flags_all(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(target="acct_any")]
        baseline = _make_baseline(recipients=[])

        findings = detector.detect(events, baseline)

        recipient_findings = [f for f in findings if f.metadata.get("type") == "new_recipient"]
        assert len(recipient_findings) == 1

    def test_no_recipients_key_flags_all(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(target="acct_any")]
        baseline = Baseline(frequency_tables={}, known_entities={}, relationships={})

        findings = detector.detect(events, baseline)

        recipient_findings = [f for f in findings if f.metadata.get("type") == "new_recipient"]
        assert len(recipient_findings) == 1

    def test_title_includes_source(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(target="acct_new", source="stripe")]
        baseline = _make_baseline(recipients=[])

        findings = detector.detect(events, baseline)

        recipient_findings = [f for f in findings if f.metadata.get("type") == "new_recipient"]
        assert "stripe" in recipient_findings[0].title


class TestAmountAboveMax:
    def test_flags_amount_above_historical_max(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(
            target="acct_known",
            source="bank-api",
            metadata={"amount": 15000},
        )]
        baseline = _make_baseline(
            recipients=["acct_known"],
            amount_maxes={"bank-api": 10000},
        )

        findings = detector.detect(events, baseline)

        amount_findings = [f for f in findings if f.metadata.get("type") == "amount_above_max"]
        assert len(amount_findings) == 1
        assert amount_findings[0].metadata["amount"] == 15000.0
        assert amount_findings[0].metadata["threshold"] == 10000.0

    def test_does_not_flag_amount_at_max(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(
            target="acct_known",
            source="bank-api",
            metadata={"amount": 10000},
        )]
        baseline = _make_baseline(
            recipients=["acct_known"],
            amount_maxes={"bank-api": 10000},
        )

        findings = detector.detect(events, baseline)

        amount_findings = [f for f in findings if f.metadata.get("type") == "amount_above_max"]
        assert len(amount_findings) == 0

    def test_does_not_flag_amount_below_max(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(
            target="acct_known",
            source="bank-api",
            metadata={"amount": 5000},
        )]
        baseline = _make_baseline(
            recipients=["acct_known"],
            amount_maxes={"bank-api": 10000},
        )

        findings = detector.detect(events, baseline)

        amount_findings = [f for f in findings if f.metadata.get("type") == "amount_above_max"]
        assert len(amount_findings) == 0

    def test_uses_global_max_when_no_source_specific(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(
            target="acct_known",
            source="new-bank",
            metadata={"amount": 25000},
        )]
        baseline = _make_baseline(
            recipients=["acct_known"],
            amount_maxes={"bank-api": 10000},
        )

        findings = detector.detect(events, baseline)

        amount_findings = [f for f in findings if f.metadata.get("type") == "amount_above_max"]
        assert len(amount_findings) == 1
        assert amount_findings[0].metadata["threshold"] == 10000.0

    def test_no_amount_in_metadata_no_finding(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(
            target="acct_known",
            source="bank-api",
            metadata={},
        )]
        baseline = _make_baseline(
            recipients=["acct_known"],
            amount_maxes={"bank-api": 10000},
        )

        findings = detector.detect(events, baseline)

        amount_findings = [f for f in findings if f.metadata.get("type") == "amount_above_max"]
        assert len(amount_findings) == 0

    def test_no_historical_max_no_finding(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(
            target="acct_known",
            source="bank-api",
            metadata={"amount": 99999},
        )]
        baseline = _make_baseline(recipients=["acct_known"])

        findings = detector.detect(events, baseline)

        amount_findings = [f for f in findings if f.metadata.get("type") == "amount_above_max"]
        assert len(amount_findings) == 0


class TestEventTypeFiltering:
    def test_ignores_non_financial_event_types(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(event_type="login", target="acct_unknown")]
        baseline = _make_baseline(recipients=["acct_known"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_handles_transaction_type(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(event_type="transaction", target="acct_new")]
        baseline = _make_baseline(recipients=[])

        findings = detector.detect(events, baseline)

        assert len([f for f in findings if f.metadata.get("type") == "new_recipient"]) == 1

    def test_handles_payment_type(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(event_type="payment", target="acct_new")]
        baseline = _make_baseline(recipients=[])

        findings = detector.detect(events, baseline)

        assert len([f for f in findings if f.metadata.get("type") == "new_recipient"]) == 1

    def test_handles_withdrawal_type(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(event_type="withdrawal", target="acct_new")]
        baseline = _make_baseline(recipients=[])

        findings = detector.detect(events, baseline)

        assert len([f for f in findings if f.metadata.get("type") == "new_recipient"]) == 1


class TestCombinedDetection:
    def test_both_new_recipient_and_high_amount(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(
            target="acct_unknown",
            source="bank-api",
            metadata={"amount": 50000},
        )]
        baseline = _make_baseline(
            recipients=["acct_known"],
            amount_maxes={"bank-api": 10000},
        )

        findings = detector.detect(events, baseline)

        types = {f.metadata["type"] for f in findings}
        assert "new_recipient" in types
        assert "amount_above_max" in types


class TestEdgeCases:
    def test_no_events_no_findings(self) -> None:
        detector = FinancialAnomalyDetector()
        findings = detector.detect([], _make_baseline(recipients=["acct_known"]))
        assert len(findings) == 0

    def test_finding_status_is_open(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(target="acct_new")]
        baseline = _make_baseline(recipients=[])

        findings = detector.detect(events, baseline)

        assert all(f.status == FindingStatus.OPEN for f in findings)

    def test_relevant_sources_returns_none(self) -> None:
        detector = FinancialAnomalyDetector()
        assert detector.relevant_sources() is None

    def test_relevant_event_types_returns_financial_types(self) -> None:
        detector = FinancialAnomalyDetector()
        types = detector.relevant_event_types()
        assert types is not None
        assert set(types) == {"transaction", "transfer", "payment", "withdrawal"}

    def test_string_amount_in_metadata(self) -> None:
        detector = FinancialAnomalyDetector()
        events = [_make_event(
            target="acct_known",
            source="bank-api",
            metadata={"amount": "15000"},
        )]
        baseline = _make_baseline(
            recipients=["acct_known"],
            amount_maxes={"bank-api": 10000},
        )

        findings = detector.detect(events, baseline)

        amount_findings = [f for f in findings if f.metadata.get("type") == "amount_above_max"]
        assert len(amount_findings) == 1
