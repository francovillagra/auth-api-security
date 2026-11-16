"""init.py: credenciales, datos de práctica y carpeta compartida. Y que lo que genera cumple las mismas reglas que exige la API."""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import pytest

import init
from common import (
    ADMIN_EMAIL, ADMIN_PASSWORD_FILE, API_UID, CONSOLE_UID, MAIL_DOMAIN, SAMPLE_CUSTOMERS, SECRET_FILES, SEED_FILE, SERVER_LOG, TARGET_EMAIL,
)

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture()
def dirs(tmp_path, monkeypatch):
    state, shared = tmp_path / "state", tmp_path / "shared"
    state.mkdir()
    monkeypatch.setattr(init, "STATE_DIR", state)
    monkeypatch.setattr(init, "SHARED_DIR", shared)
    return state, shared


# -- credenciales ---------------------------------------------------------------------------------------------------------------------------------

def test_secrets_are_created_once_and_never_changed(dirs):
    state, _ = dirs
    assert init.ensure_secrets() is True
    first = {name: (state / name).read_text() for name in SECRET_FILES}
    assert init.ensure_secrets() is False
    assert {name: (state / name).read_text() for name in SECRET_FILES} == first
    assert set(first) == {"postgres_password", "jwt_secret", "jwt_refresh_secret", ADMIN_PASSWORD_FILE}
    assert all(value.endswith("\n") and value.strip() for value in first.values())


def test_a_missing_or_empty_secret_is_regenerated_without_touching_the_others(dirs):
    state, _ = dirs
    init.ensure_secrets()
    keep = (state / "jwt_secret").read_text()
    (state / ADMIN_PASSWORD_FILE).write_text("   \n")
    (state / "postgres_password").unlink()
    assert init.ensure_secrets() is True
    assert (state / "jwt_secret").read_text() == keep
    assert (state / ADMIN_PASSWORD_FILE).read_text().strip() and (state / "postgres_password").read_text().strip()


def test_the_signing_secrets_meet_the_rules_the_api_enforces_and_differ(dirs):
    state, _ = dirs
    init.ensure_secrets()
    access, refresh = (init.read_text(state / name) for name in ("jwt_secret", "jwt_refresh_secret"))
    assert access != refresh
    for secret in (access, refresh):
        assert init.is_valid_jwt_secret(secret) and len(secret) >= 32 and len(set(secret)) >= 10
    password = init.read_text(state / ADMIN_PASSWORD_FILE)
    assert 8 <= len(password.encode()) <= 72                    # bcrypt solo usa los primeros 72 bytes


@pytest.mark.parametrize("value", [
    "short", "x" * 31, "change-this-" + "a1B2c3D4e5F6" * 3, "REEMPLAZAR" + "abcdefghij" * 3, "your_secret_" + "0123456789abcdef" * 2,
    "secreto-seguro" + "q1w2e3r4t5y6u7i8o9p0" * 2, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "openssl-rand-" + "9f8e7d6c5b4a" * 3,
])
def test_values_the_api_would_reject_are_not_valid_secrets(value):
    assert init.is_valid_jwt_secret(value) is False


def test_the_secret_rules_are_the_same_as_the_ones_in_the_api_source():
    source = (REPO / "lib" / "secrets.ts").read_text(encoding="utf-8")
    assert re.search(r"MIN_SECRET_LENGTH = (\d+)", source).group(1) == str(init.MIN_SECRET_LENGTH)
    assert re.search(r"new Set\(value\)\.size < (\d+)", source).group(1) == str(init.MIN_DISTINCT_CHARS)
    pattern = re.search(r"const PLACEHOLDER = /(.+)/i;", source).group(1)
    assert pattern == init.PLACEHOLDER.pattern


def test_secrets_are_readable_by_every_demo_user_and_writable_only_by_the_owner(dirs):
    state, _ = dirs
    init.ensure_secrets()
    init.write_seed()
    for name in (*SECRET_FILES, SEED_FILE):
        mode = stat.S_IMODE((state / name).stat().st_mode)
        assert mode == 0o644, (name, oct(mode))
    assert not list(state.glob("*.tmp"))


# -- datos de práctica ----------------------------------------------------------------------------------------------------------------------------------

def test_the_seed_names_who_is_loaded_and_carries_no_passwords(dirs):
    state, _ = dirs
    init.write_seed()
    text = (state / SEED_FILE).read_text(encoding="utf-8")
    seed = json.loads(text)
    assert seed["admin"] == {"email": ADMIN_EMAIL, "name": "Administración (práctica)"}
    assert [c["email"] for c in seed["customers"]] == [email for _, email in SAMPLE_CUSTOMERS]
    assert "password" not in text.lower() and "contraseña" not in text.lower()


def test_every_practice_address_is_in_the_reserved_test_domain():
    emails = [ADMIN_EMAIL, *(email for _, email in SAMPLE_CUSTOMERS)]
    assert all(email.endswith("@" + MAIL_DOMAIN) for email in emails)
    assert MAIL_DOMAIN.endswith(".test")                        # RFC 6761: no existe en internet
    assert TARGET_EMAIL == SAMPLE_CUSTOMERS[0][1]


# -- carpeta compartida -----------------------------------------------------------------------------------------------------------------------------------

def test_the_shared_folder_is_created_and_the_old_log_is_removed(dirs):
    _, shared = dirs
    shared.mkdir()
    (shared / SERVER_LOG).write_text("registro viejo\n")
    init.reset_shared()
    assert shared.is_dir() and not (shared / SERVER_LOG).exists()
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755


def test_ownership_is_only_changed_when_running_as_root(dirs, monkeypatch):
    _, shared = dirs
    calls = []
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: calls.append((Path(path).name, uid, gid)))
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    init.reset_shared()
    assert calls == []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    init.reset_shared()
    assert calls == [("shared", API_UID, API_UID)]               # la carpeta queda a nombre del usuario de la API


def test_main_prints_status_lines_and_no_credentials(dirs, capsys):
    state, shared = dirs
    assert init.main() == 0
    first = capsys.readouterr().out
    assert init.main() == 0
    second = capsys.readouterr().out
    assert "generadas" in first and "ya existían" in second
    for name in SECRET_FILES:
        value = (state / name).read_text().strip()
        assert value not in first and value not in second
    assert shared.is_dir() and (state / SEED_FILE).exists()


def test_the_users_the_services_run_as_are_not_root():
    assert API_UID == 1000 and CONSOLE_UID == 10002 and 0 not in (API_UID, CONSOLE_UID)
