"""Tests for billing integration — service-side and client-side."""
import hashlib
import hmac
import json
import importlib
import importlib.util
import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock

# Add services to path so we can import billing module directly
_services_path = os.path.join(os.path.dirname(__file__), "..", "..", "services", "account")
sys.path.insert(0, os.path.abspath(_services_path))

# Load mallcop.pro via importlib to avoid stale editable-install cache
_pro_path = os.path.join(os.path.dirname(__file__), "..", "..", "src", "mallcop", "pro.py")
_pro_path = os.path.abspath(_pro_path)
_pro_spec = importlib.util.spec_from_file_location("mallcop.pro", _pro_path)
_pro_mod = importlib.util.module_from_spec(_pro_spec)
sys.modules["mallcop.pro"] = _pro_mod
_pro_spec.loader.exec_module(_pro_mod)


# ---------------------------------------------------------------------------
# Service-side: billing.py
# ---------------------------------------------------------------------------

class TestBillingModule:
    """Test the billing module functions."""

    def test_get_plan_info_small(self):
        from billing import get_plan_info
        info = get_plan_info("small")
        assert info is not None
        assert info["amount"] == 2900
        assert info["connectors"] == 2
        assert info["events_per_day"] == 1000

    def test_get_plan_info_medium(self):
        from billing import get_plan_info
        info = get_plan_info("medium")
        assert info is not None
        assert info["amount"] == 5900
        assert info["connectors"] == 5

    def test_get_plan_info_large(self):
        from billing import get_plan_info
        info = get_plan_info("large")
        assert info is not None
        assert info["amount"] == 9900

    def test_get_plan_info_unknown(self):
        from billing import get_plan_info
        assert get_plan_info("enterprise") is None

    def test_check_plan_limits_within(self):
        from billing import check_plan_limits
        violations = check_plan_limits("small", 2, 500)
        assert violations == []

    def test_check_plan_limits_connector_exceeded(self):
        from billing import check_plan_limits
        violations = check_plan_limits("small", 5, 500)
        assert len(violations) == 1
        assert "Connector limit" in violations[0]

    def test_check_plan_limits_events_exceeded(self):
        from billing import check_plan_limits
        violations = check_plan_limits("small", 1, 2000)
        assert len(violations) == 1
        assert "Daily event limit" in violations[0]

    def test_check_plan_limits_both_exceeded(self):
        from billing import check_plan_limits
        violations = check_plan_limits("small", 5, 2000)
        assert len(violations) == 2

    def test_check_plan_limits_unknown_plan(self):
        from billing import check_plan_limits
        violations = check_plan_limits("enterprise", 1, 1)
        assert len(violations) == 1
        assert "Unknown plan" in violations[0]

    def test_create_checkout_success(self):
        from billing import create_checkout
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"url": "https://checkout.stripe.com/test"}

        with patch("billing.STRIPE_API_KEY", "sk_test_fake"), \
             patch("billing.requests.post", return_value=mock_resp) as mock_post:
            url = create_checkout("acct_123", "small")
        assert url == "https://checkout.stripe.com/test"
        # Verify the Stripe API was called with correct data
        call_kwargs = mock_post.call_args
        assert "checkout/sessions" in call_kwargs[0][0] or "checkout/sessions" in str(call_kwargs)

    def test_create_checkout_unknown_plan(self):
        from billing import create_checkout
        with patch("billing.STRIPE_API_KEY", "sk_test_fake"):
            with pytest.raises(ValueError, match="Unknown plan"):
                create_checkout("acct_123", "enterprise")

    def test_create_checkout_stripe_error(self):
        from billing import create_checkout
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad request"

        with patch("billing.STRIPE_API_KEY", "sk_test_fake"), \
             patch("billing.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="Stripe checkout creation failed"):
                create_checkout("acct_123", "small")

    def test_handle_checkout_completed(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        event = {
            "type": "checkout.session.completed",
            "data": {"object": {
                "client_reference_id": "acct_123",
                "metadata": {"plan_tier": "medium"},
                "customer": "cus_abc",
                "subscription": "sub_xyz",
            }},
        }
        handle_stripe_event(json.dumps(event).encode(), mock_db)
        mock_db.update_account.assert_called_once_with(
            "acct_123",
            plan_tier="medium",
            status="active",
            stripe_customer_id="cus_abc",
            stripe_subscription_id="sub_xyz",
        )

    def test_handle_checkout_completed_fallback_account_id(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        event = {
            "type": "checkout.session.completed",
            "data": {"object": {
                "client_reference_id": "",
                "metadata": {"account_id": "acct_456", "plan_tier": "large"},
                "customer": "cus_def",
                "subscription": "sub_uvw",
            }},
        }
        handle_stripe_event(json.dumps(event).encode(), mock_db)
        mock_db.update_account.assert_called_once_with(
            "acct_456",
            plan_tier="large",
            status="active",
            stripe_customer_id="cus_def",
            stripe_subscription_id="sub_uvw",
        )

    def test_handle_payment_failed(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        mock_db.get_account_by_subscription_id.return_value = {"account_id": "acct_pay"}
        event = {
            "type": "invoice.payment_failed",
            "data": {"object": {"subscription": "sub_123"}},
        }
        # Should not raise
        handle_stripe_event(json.dumps(event).encode(), mock_db)
        mock_db.update_account.assert_called_once_with("acct_pay", status="suspended")

    def test_handle_subscription_deleted(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        mock_db.get_account_by_subscription_id.return_value = {"account_id": "acct_del"}
        event = {
            "type": "customer.subscription.deleted",
            "data": {"object": {"id": "sub_123"}},
        }
        handle_stripe_event(json.dumps(event).encode(), mock_db)
        mock_db.update_account.assert_called_once_with("acct_del", status="cancelled")

    def test_handle_unknown_event(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        event = {"type": "unknown.event", "data": {"object": {}}}
        # Should not raise
        handle_stripe_event(json.dumps(event).encode(), mock_db)

    def test_handle_checkout_rejects_invalid_plan_tier(self):
        """Webhook with invalid plan_tier should not update the account."""
        from billing import handle_stripe_event
        mock_db = MagicMock()
        event = {
            "type": "checkout.session.completed",
            "data": {"object": {
                "client_reference_id": "acct_123",
                "metadata": {"plan_tier": "enterprise_evil"},
                "customer": "cus_abc",
                "subscription": "sub_xyz",
            }},
        }
        handle_stripe_event(json.dumps(event).encode(), mock_db)
        mock_db.update_account.assert_not_called()

    def test_handle_checkout_rejects_empty_plan_tier(self):
        """Webhook with empty plan_tier should not update the account."""
        from billing import handle_stripe_event
        mock_db = MagicMock()
        event = {
            "type": "checkout.session.completed",
            "data": {"object": {
                "client_reference_id": "acct_123",
                "metadata": {"plan_tier": ""},
                "customer": "cus_abc",
                "subscription": "sub_xyz",
            }},
        }
        handle_stripe_event(json.dumps(event).encode(), mock_db)
        mock_db.update_account.assert_not_called()

    def test_handle_checkout_accepts_valid_plan_tiers(self):
        """All valid plan tiers should be accepted."""
        from billing import handle_stripe_event
        for tier in ("small", "medium", "large"):
            mock_db = MagicMock()
            event = {
                "type": "checkout.session.completed",
                "data": {"object": {
                    "client_reference_id": f"acct_{tier}",
                    "metadata": {"plan_tier": tier},
                    "customer": "cus_abc",
                    "subscription": "sub_xyz",
                }},
            }
            handle_stripe_event(json.dumps(event).encode(), mock_db)
            mock_db.update_account.assert_called_once()


# ---------------------------------------------------------------------------
# Service-side: Stripe webhook signature verification
# ---------------------------------------------------------------------------

def _make_stripe_signature(payload: bytes, secret: str, timestamp: int | None = None) -> str:
    """Helper: build a valid Stripe-Signature header."""
    ts = timestamp or int(time.time())
    signed = f"{ts}.".encode() + payload
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


class TestStripeSignatureVerification:
    """Tests for verify_stripe_signature and handle_stripe_event with signatures."""

    SECRET = "whsec_test_secret_1234"

    def test_valid_signature(self):
        from billing import verify_stripe_signature
        payload = b'{"type":"checkout.session.completed"}'
        sig = _make_stripe_signature(payload, self.SECRET)
        # Should not raise
        verify_stripe_signature(payload, sig, self.SECRET)

    def test_invalid_signature(self):
        from billing import verify_stripe_signature
        payload = b'{"type":"checkout.session.completed"}'
        sig = _make_stripe_signature(payload, "wrong_secret")
        with pytest.raises(ValueError, match="Signature verification failed"):
            verify_stripe_signature(payload, sig, self.SECRET)

    def test_tampered_payload(self):
        from billing import verify_stripe_signature
        payload = b'{"type":"checkout.session.completed"}'
        sig = _make_stripe_signature(payload, self.SECRET)
        tampered = b'{"type":"checkout.session.completed","extra":"evil"}'
        with pytest.raises(ValueError, match="Signature verification failed"):
            verify_stripe_signature(tampered, sig, self.SECRET)

    def test_missing_secret(self):
        from billing import verify_stripe_signature
        with pytest.raises(ValueError, match="Webhook secret not configured"):
            verify_stripe_signature(b"x", "t=1,v1=abc", "")

    def test_missing_sig_header(self):
        from billing import verify_stripe_signature
        with pytest.raises(ValueError, match="Missing signature header"):
            verify_stripe_signature(b"x", "", self.SECRET)

    def test_malformed_sig_header(self):
        from billing import verify_stripe_signature
        with pytest.raises(ValueError, match="Invalid signature header format"):
            verify_stripe_signature(b"x", "garbage", self.SECRET)

    def test_expired_timestamp(self):
        from billing import verify_stripe_signature
        payload = b'{"type":"test"}'
        old_ts = int(time.time()) - 600  # 10 minutes ago
        sig = _make_stripe_signature(payload, self.SECRET, timestamp=old_ts)
        with pytest.raises(ValueError, match="outside tolerance"):
            verify_stripe_signature(payload, sig, self.SECRET)

    def test_handle_stripe_event_with_valid_signature(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        event = {
            "type": "checkout.session.completed",
            "data": {"object": {
                "client_reference_id": "acct_sig",
                "metadata": {"plan_tier": "small"},
                "customer": "cus_s",
                "subscription": "sub_s",
            }},
        }
        payload = json.dumps(event).encode()
        sig = _make_stripe_signature(payload, self.SECRET)

        with patch("billing.STRIPE_WEBHOOK_SECRET", self.SECRET):
            handle_stripe_event(payload, mock_db, sig_header=sig)
        mock_db.update_account.assert_called_once()

    def test_handle_stripe_event_with_invalid_signature(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        payload = b'{"type":"test","data":{"object":{}}}'
        bad_sig = _make_stripe_signature(payload, "wrong_secret")

        with patch("billing.STRIPE_WEBHOOK_SECRET", self.SECRET):
            with pytest.raises(ValueError, match="Signature verification failed"):
                handle_stripe_event(payload, mock_db, sig_header=bad_sig)
        mock_db.update_account.assert_not_called()

    def test_handle_stripe_event_missing_webhook_secret_env(self):
        from billing import handle_stripe_event
        mock_db = MagicMock()
        payload = b'{"type":"test","data":{"object":{}}}'

        with patch("billing.STRIPE_WEBHOOK_SECRET", ""):
            with pytest.raises(ValueError, match="STRIPE_WEBHOOK_SECRET"):
                handle_stripe_event(payload, mock_db, sig_header="t=1,v1=abc")

    def test_handle_stripe_event_dict_rejected(self):
        """Dict payload must be rejected — only bytes accepted."""
        from billing import handle_stripe_event
        mock_db = MagicMock()
        event = {"type": "unknown.event", "data": {"object": {}}}
        with pytest.raises(TypeError, match="payload must be bytes"):
            handle_stripe_event(event, mock_db)


# ---------------------------------------------------------------------------
# Service-side: app.py handlers
# ---------------------------------------------------------------------------

try:
    from app import MemoryDB, handle_record_usage, handle_get_usage, handle_subscribe, handle_webhook
    _APP_AVAILABLE = True
except ImportError:
    _APP_AVAILABLE = False


@pytest.mark.skipif(not _APP_AVAILABLE, reason="Service app module not importable")
class TestAppHandlers:
    """Test the account service request handlers."""

    def test_record_usage_success(self):
        from app import MemoryDB, handle_record_usage
        db = MemoryDB()
        db.create_account("acct_1", "test@example.com")
        result = handle_record_usage("acct_1", {"model": "claude-3", "input_tokens": 100, "output_tokens": 50}, db)
        assert result["status"] == "ok"

    def test_record_usage_not_found(self):
        from app import MemoryDB, handle_record_usage
        db = MemoryDB()
        result = handle_record_usage("missing", {"model": "claude-3", "input_tokens": 100, "output_tokens": 50}, db)
        assert result["status"] == 404

    def test_get_usage_success(self):
        from app import MemoryDB, handle_get_usage, handle_record_usage
        db = MemoryDB()
        db.create_account("acct_1", "test@example.com")
        handle_record_usage("acct_1", {"model": "claude-3", "input_tokens": 100, "output_tokens": 50}, db)
        handle_record_usage("acct_1", {"model": "claude-3", "input_tokens": 200, "output_tokens": 100}, db)
        usage = handle_get_usage("acct_1", db)
        assert usage["input_tokens"] == 300
        assert usage["output_tokens"] == 150
        assert usage["total_tokens"] == 450
        assert usage["requests"] == 2

    def test_get_usage_not_found(self):
        from app import MemoryDB, handle_get_usage
        db = MemoryDB()
        result = handle_get_usage("missing", db)
        assert result["status"] == 404

    def test_subscribe_success(self):
        from app import MemoryDB, handle_subscribe
        db = MemoryDB()
        db.create_account("acct_1", "test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"url": "https://checkout.stripe.com/test"}
        with patch("app.create_checkout", return_value="https://checkout.stripe.com/test"):
            result = handle_subscribe("acct_1", {"plan_tier": "small"}, db)
        assert result["checkout_url"] == "https://checkout.stripe.com/test"

    def test_subscribe_not_found(self):
        from app import MemoryDB, handle_subscribe
        db = MemoryDB()
        result = handle_subscribe("missing", {"plan_tier": "small"}, db)
        assert result["status"] == 404

    def test_webhook_handler(self):
        from app import MemoryDB, handle_webhook
        db = MemoryDB()
        db.create_account("acct_1", "test@example.com")
        event = {
            "type": "checkout.session.completed",
            "data": {"object": {
                "client_reference_id": "acct_1",
                "metadata": {"plan_tier": "medium"},
                "customer": "cus_abc",
                "subscription": "sub_xyz",
            }},
        }
        result = handle_webhook(json.dumps(event).encode(), db)
        assert result["status"] == "ok"
        acct = db.get_account("acct_1")
        assert acct.plan_tier == "medium"
        assert acct.status == "active"
        assert acct.stripe_customer_id == "cus_abc"

    def test_memory_db_update_account(self):
        from app import MemoryDB
        db = MemoryDB()
        db.create_account("acct_1", "test@example.com")
        db.update_account("acct_1", plan_tier="large", status="active")
        acct = db.get_account("acct_1")
        assert acct.plan_tier == "large"
        assert acct.status == "active"

    def test_memory_db_update_nonexistent(self):
        from app import MemoryDB
        db = MemoryDB()
        result = db.update_account("missing", plan_tier="large")
        assert result is None


# ---------------------------------------------------------------------------
# Client-side: ProClient billing methods
# ---------------------------------------------------------------------------

class TestProClientBilling:
    """Test ProClient billing methods."""

    def test_subscribe(self):
        from mallcop.pro import ProClient
        client = ProClient("http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"checkout_url": "https://checkout.stripe.com/test"}

        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            url = client.subscribe("acct_123", "small", "token123")
        assert url == "https://checkout.stripe.com/test"

    def test_subscribe_failure(self):
        from mallcop.pro import ProClient
        client = ProClient("http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal error"

        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="ProClient.subscribe"):
                client.subscribe("acct_123", "small", "token123")

    def test_check_subscription(self):
        from mallcop.pro import ProClient
        client = ProClient("http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "plan_tier": "medium", "status": "active",
            "account_id": "x", "email": "x", "created_at": "x",
        }

        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            info = client.check_subscription("acct_123", "token123")
        assert info["plan_tier"] == "medium"
        assert info["status"] == "active"

    def test_check_subscription_failure(self):
        from mallcop.pro import ProClient
        client = ProClient("http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            with pytest.raises(RuntimeError):
                client.check_subscription("acct_123", "token123")

    def test_record_usage(self):
        from mallcop.pro import ProClient
        client = ProClient("http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok"}

        with patch("mallcop.pro.requests.post", return_value=mock_resp):
            result = client.record_usage("acct_123", "claude-3", 100, 50, "token123")
        assert result["status"] == "ok"

    def test_get_usage(self):
        from mallcop.pro import ProClient
        client = ProClient("http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "input_tokens": 1000, "output_tokens": 500,
            "total_tokens": 1500, "requests": 10,
        }

        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            usage = client.get_usage("acct_123", "token123")
        assert usage["total_tokens"] == 1500
        assert usage["requests"] == 10

    def test_get_usage_failure(self):
        from mallcop.pro import ProClient
        client = ProClient("http://localhost:8000")
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with patch("mallcop.pro.requests.get", return_value=mock_resp):
            with pytest.raises(RuntimeError):
                client.get_usage("acct_123", "token123")

    def test_url_trailing_slash_stripped(self):
        from mallcop.pro import ProClient
        client = ProClient("http://localhost:8000/")
        assert client._url == "http://localhost:8000"
