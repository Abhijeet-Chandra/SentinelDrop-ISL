from sqlalchemy import create_engine, text


def test_schema_upgrade_preserves_legacy_rows_and_is_idempotent(tmp_path, monkeypatch):
    database_path = tmp_path / "copied-legacy.sqlite3"
    legacy_engine = create_engine(f"sqlite:///{database_path}")
    with legacy_engine.begin() as connection:
        connection.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(50) NOT NULL, password_hash VARCHAR(255) NOT NULL, created_at DATETIME NOT NULL)"))
        connection.execute(text("CREATE TABLE auth_tokens (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, token_hash VARCHAR(64) NOT NULL, created_at DATETIME NOT NULL)"))
        connection.execute(text("CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, event_type VARCHAR(100) NOT NULL, session_id VARCHAR(255), details VARCHAR(1000) NOT NULL, previous_hash VARCHAR(64), entry_hash VARCHAR(64) NOT NULL, created_at DATETIME NOT NULL)"))
        connection.execute(text("CREATE TABLE user_identities (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, public_key VARCHAR(255) NOT NULL, fingerprint VARCHAR(95) NOT NULL, created_at DATETIME NOT NULL)"))
        connection.execute(text("CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id VARCHAR(255) NOT NULL, sequence_number INTEGER NOT NULL, message_type VARCHAR(50) NOT NULL, sender_user_id INTEGER, recipient_user_id INTEGER, sent_at DATETIME, ciphertext_hash VARCHAR(64), ciphertext TEXT, nonce VARCHAR(64), created_at DATETIME NOT NULL)"))
        connection.execute(text("INSERT INTO users VALUES (1, 'preserved-user', 'hash', '2026-10-01 00:00:00')"))
        connection.execute(text("INSERT INTO auth_tokens VALUES (1, 1, 'token-hash', '2026-10-01 00:00:00')"))
        connection.execute(text("INSERT INTO messages VALUES (1, 'old-session', 7, 'text', 1, 2, NULL, 'cipher-hash', 'aabb', 'unique-nonce', '2026-10-01 00:00:00')"))

    import app.database.init_db as migration

    monkeypatch.setattr(migration, "engine", legacy_engine)
    migration.init_db()
    migration.init_db()

    with legacy_engine.connect() as connection:
        assert connection.execute(text("SELECT username FROM users WHERE id = 1")).scalar_one() == "preserved-user"
        assert connection.execute(text("SELECT token_hash FROM auth_tokens WHERE id = 1")).scalar_one() == "token-hash"
        assert connection.execute(text("SELECT ciphertext FROM messages WHERE id = 1")).scalar_one() == "aabb"
        assert connection.execute(text("SELECT sent_at FROM messages WHERE id = 1")).scalar_one() == "2026-10-01 00:00:00"
        assert connection.execute(text("SELECT nonce FROM used_message_nonces WHERE session_id = 'old-session'")).scalar_one() == "unique-nonce"
        assert {row[1] for row in connection.execute(text("PRAGMA table_info(auth_tokens)"))} >= {"expires_at"}
        assert {row[1] for row in connection.execute(text("PRAGMA table_info(users)"))} >= {"is_admin"}

    legacy_engine.dispose()
