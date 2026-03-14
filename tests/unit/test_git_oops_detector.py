"""Tests for git-oops detector: repo scanning for leaked creds and antipatterns."""

from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mallcop.detectors.git_oops.detector import (
    GitOopsDetector,
    _match_file_glob,
    scan_repo,
)
from mallcop.schemas import Baseline, FindingStatus, Severity


def _empty_baseline() -> Baseline:
    return Baseline(
        frequency_tables={},
        known_entities={},
        relationships={},
    )


# --- File glob matching ---


class TestFileGlobMatching:
    def test_star_star_star(self) -> None:
        assert _match_file_glob("src/main.py", "**/*")

    def test_specific_extension(self) -> None:
        assert _match_file_glob("app.py", "**/*.py")
        assert not _match_file_glob("app.js", "**/*.py")

    def test_brace_expansion(self) -> None:
        assert _match_file_glob("app.py", "**/*.{py,js}")
        assert _match_file_glob("app.js", "**/*.{py,js}")
        assert not _match_file_glob("app.rb", "**/*.{py,js}")

    def test_dotfile_glob(self) -> None:
        assert _match_file_glob(".env", "**/.env")
        assert _match_file_glob("config/.env", "**/.env")

    def test_dockerfile_glob(self) -> None:
        assert _match_file_glob("Dockerfile", "**/Dockerfile*")
        assert _match_file_glob("Dockerfile.prod", "**/Dockerfile*")

    def test_github_workflows(self) -> None:
        assert _match_file_glob(
            ".github/workflows/ci.yml", "**/.github/workflows/*.{yml,yaml}"
        )


# --- Pattern matching: positive cases ---


class TestGitOopsPositive:
    """Each pattern should fire on its target content."""

    def test_aws_access_key(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
        findings = scan_repo(tmp_path)
        assert len(findings) == 1
        assert findings[0].metadata["pattern_id"] == "aws-access-key"
        assert findings[0].severity == Severity.CRITICAL

    def test_aws_secret_key(self, tmp_path: Path) -> None:
        (tmp_path / "settings.py").write_text(
            'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "aws-secret-key" for f in findings)

    def test_github_pat(self, tmp_path: Path) -> None:
        (tmp_path / "script.sh").write_text(
            "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "github-pat" for f in findings)

    def test_github_oauth(self, tmp_path: Path) -> None:
        (tmp_path / "auth.py").write_text(
            'token = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "github-oauth" for f in findings)

    def test_github_app_token(self, tmp_path: Path) -> None:
        (tmp_path / "bot.py").write_text(
            'token = "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "github-app-token" for f in findings)

    def test_slack_token(self, tmp_path: Path) -> None:
        (tmp_path / "notify.py").write_text(
            'SLACK_TOKEN = "xoxb-1234567890-abcdefghijklmnop"'
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "slack-token" for f in findings)

    def test_stripe_secret_key(self, tmp_path: Path) -> None:
        (tmp_path / "billing.py").write_text(
            'stripe.api_key = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZab"'
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "stripe-secret-key" for f in findings)

    def test_private_key(self, tmp_path: Path) -> None:
        (tmp_path / "key.pem").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "private-key" for f in findings)

    def test_openssh_private_key(self, tmp_path: Path) -> None:
        (tmp_path / "id_ed25519").write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn...\n-----END OPENSSH PRIVATE KEY-----"
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "private-key" for f in findings)

    def test_committed_env(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text(
            "DATABASE_URL=postgres://...\nSECRET_KEY=supersecret\n"
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "committed-env" for f in findings)

    def test_committed_env_local(self, tmp_path: Path) -> None:
        (tmp_path / ".env.local").write_text("API_KEY=abc123xyz\n")
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "committed-env-local" for f in findings)

    def test_hardcoded_password(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(
            'password = "my_super_secret_password_123"'
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "hardcoded-password" for f in findings)

    def test_hardcoded_password_yaml(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text(
            'password: "my_super_secret_password_123"'
        )
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "hardcoded-password" for f in findings)

    def test_connection_string_postgres(self, tmp_path: Path) -> None:
        (tmp_path / "db.py").write_text(
            'DATABASE_URL = "postgresql://admin:s3cret@db.example.com:5432/mydb"'
        )
        findings = scan_repo(tmp_path)
        assert any(
            f.metadata["pattern_id"] == "hardcoded-connection-string" for f in findings
        )

    def test_connection_string_mongodb(self, tmp_path: Path) -> None:
        (tmp_path / "db.py").write_text(
            'MONGO_URI = "mongodb+srv://user:pass@cluster.mongodb.net/db"'
        )
        findings = scan_repo(tmp_path)
        assert any(
            f.metadata["pattern_id"] == "hardcoded-connection-string" for f in findings
        )

    def test_gha_hardcoded_secret(self, tmp_path: Path) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "deploy.yml").write_text(
            textwrap.dedent("""\
                jobs:
                  deploy:
                    env:
                      AWS_KEY: AKIAIOSFODNN7EXAMPLE
            """)
        )
        findings = scan_repo(tmp_path)
        assert any(
            f.metadata["pattern_id"] == "gha-hardcoded-secret" for f in findings
        )

    def test_dockerfile_embedded_secret(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\nENV SECRET_KEY=mysecretvalue\nRUN pip install app\n"
        )
        findings = scan_repo(tmp_path)
        assert any(
            f.metadata["pattern_id"] == "dockerfile-embedded-secret" for f in findings
        )


# --- Pattern matching: negative cases ---


class TestGitOopsNegative:
    """These should NOT fire."""

    def test_no_findings_clean_repo(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("print('hello world')\n")
        (tmp_path / "README.md").write_text("# My Project\n")
        findings = scan_repo(tmp_path)
        assert len(findings) == 0

    def test_env_example_no_secrets(self, tmp_path: Path) -> None:
        (tmp_path / ".env.example").write_text(
            "DATABASE_URL=\nAPI_KEY=\n"
        )
        findings = scan_repo(tmp_path)
        # .env.example doesn't match .env glob, and has no values
        assert not any(f.metadata["pattern_id"] == "committed-env" for f in findings)

    def test_short_password_ignored(self, tmp_path: Path) -> None:
        """Passwords under 8 chars should not fire (too many false positives)."""
        (tmp_path / "config.py").write_text('password = "short"')
        findings = scan_repo(tmp_path)
        assert not any(
            f.metadata["pattern_id"] == "hardcoded-password" for f in findings
        )

    def test_binary_files_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"AKIAIOSFODNN7EXAMPLE")
        findings = scan_repo(tmp_path)
        assert len(findings) == 0

    def test_large_files_skipped(self, tmp_path: Path) -> None:
        large = tmp_path / "big.txt"
        large.write_text("AKIAIOSFODNN7EXAMPLE\n" * 100_000)  # ~2MB
        findings = scan_repo(tmp_path)
        assert len(findings) == 0

    def test_github_actions_secret_ref_ok(self, tmp_path: Path) -> None:
        """Using ${{ secrets.X }} is fine — that's not hardcoded."""
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            textwrap.dedent("""\
                jobs:
                  deploy:
                    env:
                      AWS_KEY: ${{ secrets.AWS_ACCESS_KEY_ID }}
            """)
        )
        findings = scan_repo(tmp_path)
        assert not any(
            f.metadata["pattern_id"] == "gha-hardcoded-secret" for f in findings
        )

    def test_dockerfile_no_secret(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\nENV APP_PORT=8080\nRUN pip install app\n"
        )
        findings = scan_repo(tmp_path)
        assert not any(
            f.metadata["pattern_id"] == "dockerfile-embedded-secret" for f in findings
        )


# --- Finding metadata and deduplication ---


class TestFindingMetadata:
    def test_finding_has_line_numbers(self, tmp_path: Path) -> None:
        (tmp_path / "leaked.py").write_text(
            "# line 1\n# line 2\nKEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        )
        findings = scan_repo(tmp_path)
        assert len(findings) == 1
        assert findings[0].metadata["line_numbers"] == [3]

    def test_multiple_matches_same_file_one_finding(self, tmp_path: Path) -> None:
        """Multiple occurrences of same pattern in one file = one finding."""
        (tmp_path / "keys.py").write_text(
            'K1 = "AKIAIOSFODNN7EXAMPLE"\nK2 = "AKIAIOSFODNN7EXAMPL2"\n'
        )
        findings = scan_repo(tmp_path)
        aws_findings = [
            f for f in findings if f.metadata["pattern_id"] == "aws-access-key"
        ]
        assert len(aws_findings) == 1
        assert aws_findings[0].metadata["match_count"] == 2

    def test_different_patterns_same_file_multiple_findings(
        self, tmp_path: Path
    ) -> None:
        """Different pattern types in one file = separate findings."""
        (tmp_path / "config.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'GH_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n'
        )
        findings = scan_repo(tmp_path)
        pattern_ids = {f.metadata["pattern_id"] for f in findings}
        assert "aws-access-key" in pattern_ids
        assert "github-pat" in pattern_ids

    def test_finding_status_and_detector(self, tmp_path: Path) -> None:
        (tmp_path / "leak.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
        findings = scan_repo(tmp_path)
        assert findings[0].detector == "git-oops"
        assert findings[0].status == FindingStatus.OPEN
        assert findings[0].event_ids == []

    def test_finding_title_includes_file_and_description(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "leak.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
        findings = scan_repo(tmp_path)
        assert "leak.py" in findings[0].title
        assert "git-oops" in findings[0].title


# --- Subdirectory scanning ---


class TestSubdirectoryScanning:
    def test_finds_secrets_in_subdirs(self, tmp_path: Path) -> None:
        subdir = tmp_path / "src" / "config"
        subdir.mkdir(parents=True)
        (subdir / "settings.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
        findings = scan_repo(tmp_path)
        assert len(findings) == 1
        assert findings[0].metadata["file"] == "src/config/settings.py"

    def test_nested_env_file(self, tmp_path: Path) -> None:
        subdir = tmp_path / "services" / "api"
        subdir.mkdir(parents=True)
        (subdir / ".env").write_text("SECRET_KEY=production_secret\n")
        findings = scan_repo(tmp_path)
        assert any(f.metadata["pattern_id"] == "committed-env" for f in findings)


# --- Custom patterns ---


class TestCustomPatterns:
    def test_scan_with_custom_patterns(self, tmp_path: Path) -> None:
        (tmp_path / "data.txt").write_text("SSN: 123-45-6789")
        custom = [
            {
                "id": "ssn",
                "description": "Social Security Number",
                "file_glob": "**/*",
                "regex": r"\d{3}-\d{2}-\d{4}",
                "severity": "critical",
            }
        ]
        findings = scan_repo(tmp_path, patterns=custom)
        assert len(findings) == 1
        assert findings[0].metadata["pattern_id"] == "ssn"

    def test_custom_patterns_file(self, tmp_path: Path) -> None:
        import yaml

        patterns_file = tmp_path / "custom_patterns.yaml"
        patterns_file.write_text(
            yaml.dump(
                {
                    "patterns": [
                        {
                            "id": "test-secret",
                            "description": "Test secret marker",
                            "file_glob": "**/*",
                            "regex": "TESTSECRET_[A-Z]{10}",
                            "severity": "warn",
                        }
                    ]
                }
            )
        )
        scan_dir = tmp_path / "repo"
        scan_dir.mkdir()
        (scan_dir / "app.py").write_text('KEY = "TESTSECRET_ABCDEFGHIJ"')
        findings = scan_repo(scan_dir, patterns_path=patterns_file)
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARN


# --- DetectorBase interface ---


class TestGitOopsDetectorInterface:
    def test_relevant_sources_empty(self) -> None:
        detector = GitOopsDetector()
        assert detector.relevant_sources() == []

    def test_relevant_event_types_empty(self) -> None:
        detector = GitOopsDetector()
        assert detector.relevant_event_types() == []

    def test_detect_scans_repo_paths(self, tmp_path: Path) -> None:
        (tmp_path / "leak.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
        detector = GitOopsDetector(repo_paths=[tmp_path])
        findings = detector.detect([], _empty_baseline())
        assert len(findings) == 1

    def test_detect_multiple_repos(self, tmp_path: Path) -> None:
        repo1 = tmp_path / "repo1"
        repo2 = tmp_path / "repo2"
        repo1.mkdir()
        repo2.mkdir()
        (repo1 / "a.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
        (repo2 / "b.py").write_text(
            'TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        )
        detector = GitOopsDetector(repo_paths=[repo1, repo2])
        findings = detector.detect([], _empty_baseline())
        assert len(findings) == 2

    def test_detect_nonexistent_path_skipped(self, tmp_path: Path) -> None:
        detector = GitOopsDetector(repo_paths=[tmp_path / "nonexistent"])
        findings = detector.detect([], _empty_baseline())
        assert len(findings) == 0
