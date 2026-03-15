"""Tests for BedrockClient.from_profile() credential resolution."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import sys

import pytest

from mallcop.llm.bedrock import BedrockClient


class TestFromProfile:
    def test_extracts_credentials(self):
        frozen = MagicMock()
        frozen.access_key = "AKIA_TEST"
        frozen.secret_key = "secret_test"
        frozen.token = "session_token_test"

        creds = MagicMock()
        creds.get_frozen_credentials.return_value = frozen

        session = MagicMock()
        session.get_credentials.return_value = creds

        with patch.dict(sys.modules, {"boto3": MagicMock()}):
            import boto3
            boto3.Session.return_value = session

            client = BedrockClient.from_profile("us.anthropic.claude-3-5-sonnet-20241022-v2:0", region="us-west-2")

        assert client._access_key == "AKIA_TEST"
        assert client._secret_key == "secret_test"
        assert client._session_token == "session_token_test"
        assert client._region == "us-west-2"

    def test_session_token_none_becomes_empty(self):
        frozen = MagicMock()
        frozen.access_key = "AKIA_TEST"
        frozen.secret_key = "secret_test"
        frozen.token = None

        creds = MagicMock()
        creds.get_frozen_credentials.return_value = frozen

        session = MagicMock()
        session.get_credentials.return_value = creds

        with patch.dict(sys.modules, {"boto3": MagicMock()}):
            import boto3
            boto3.Session.return_value = session

            client = BedrockClient.from_profile("us.anthropic.claude-3-5-sonnet-20241022-v2:0")

        assert client._session_token == ""

    def test_no_credentials_raises_runtime_error(self):
        session = MagicMock()
        session.get_credentials.return_value = None

        with patch.dict(sys.modules, {"boto3": MagicMock()}):
            import boto3
            boto3.Session.return_value = session

            with pytest.raises(RuntimeError, match="No AWS credentials found"):
                BedrockClient.from_profile("us.anthropic.claude-3-5-sonnet-20241022-v2:0")

    def test_no_boto3_raises_import_error(self):
        # Remove boto3 from modules and make import fail
        with patch.dict(sys.modules, {"boto3": None}):
            with pytest.raises(ImportError, match="boto3 is required"):
                BedrockClient.from_profile("us.anthropic.claude-3-5-sonnet-20241022-v2:0")
