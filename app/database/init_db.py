from sqlalchemy import text

from app.database.connection import Base, engine
from app.database.models import (  # noqa: F401
    AuditLog,
    AuthToken,
    Message,
    RelaySession,
    TrustedDevice,
    TrustedDeviceApproval,
    User,
    UserIdentity,
    UsedMessageNonce,
)


def migrate_audit_log_columns() -> None:
    """Add optional audit columns without rebuilding existing tables."""

    with engine.connect() as connection:
        columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(audit_logs)"))
        }
        if "actor_id" not in columns:
            connection.execute(
                text("ALTER TABLE audit_logs ADD COLUMN actor_id VARCHAR(100)")
            )
        if "status" not in columns:
            connection.execute(
                text("ALTER TABLE audit_logs ADD COLUMN status VARCHAR(50)")
            )
        connection.commit()


def migrate_admin_and_message_columns() -> None:
    """Add role and encrypted-transfer audit columns to existing SQLite databases."""
    with engine.connect() as connection:
        auth_token_columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(auth_tokens)"))
        }
        if "expires_at" not in auth_token_columns:
            connection.execute(text("ALTER TABLE auth_tokens ADD COLUMN expires_at DATETIME"))

        user_columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(users)"))
        }
        if "is_admin" not in user_columns:
            connection.execute(
                text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0")
            )

        identity_columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(user_identities)"))
        }
        if "client_managed" not in identity_columns:
            connection.execute(
                text("ALTER TABLE user_identities ADD COLUMN client_managed BOOLEAN NOT NULL DEFAULT 0")
            )

        message_columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(messages)"))
        }
        additions = {
            "sender_user_id": "INTEGER",
            "recipient_user_id": "INTEGER",
            "sent_at": "DATETIME",
            "received_at": "DATETIME",
            "ciphertext_hash": "VARCHAR(64)",
            "ciphertext": "TEXT",
            "nonce": "VARCHAR(64)",
            "filename": "VARCHAR(255)",
            "mime_type": "VARCHAR(255)",
            "file_size": "INTEGER",
            "signature": "TEXT",
            "signature_payload": "TEXT",
            "signature_algorithm": "VARCHAR(100)",
        }
        for column, sql_type in additions.items():
            if column not in message_columns:
                connection.execute(
                    text(f"ALTER TABLE messages ADD COLUMN {column} {sql_type}")
                )
        connection.execute(
            text("UPDATE messages SET sent_at = created_at WHERE sent_at IS NULL")
        )
        # Preserve existing message rows while carrying forward their unique nonce values.
        # Historical duplicate nonce rows are ignored here; new submissions use the
        # separately constrained registry table and are rejected on collision.
        connection.execute(
            text(
                "INSERT OR IGNORE INTO used_message_nonces (session_id, sender_user_id, nonce) "
                "SELECT DISTINCT session_id, sender_user_id, nonce FROM messages "
                "WHERE session_id IS NOT NULL AND sender_user_id IS NOT NULL "
                "AND nonce IS NOT NULL AND nonce != ''"
            )
        )
        connection.commit()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    migrate_audit_log_columns()
    migrate_admin_and_message_columns()


if __name__ == "__main__":
    init_db()
    print("SentinelDrop database initialized.")
