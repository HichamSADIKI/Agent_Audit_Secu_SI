"""index unique partiel : une seule alerte ouverte par (machine, type)

Rend l'ouverture d'alerte idempotente sous concurrence (plusieurs workers API
+ scheduler) : INSERT ... ON CONFLICT DO NOTHING s'appuie sur cet index.

Revision ID: 0003_alert_open_unique
Revises: 0002_hostname_nullable
Create Date: 2026-05-30

"""
from alembic import op
import sqlalchemy as sa

revision = "0003_alert_open_unique"
down_revision = "0002_hostname_nullable"
branch_labels = None
depends_on = None

INDEX_NAME = "uq_alerts_open_per_machine_type"


def upgrade() -> None:
    op.create_index(
        INDEX_NAME,
        "alerts",
        ["machine_id", "type"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
    )


def downgrade() -> None:
    op.drop_index(INDEX_NAME, table_name="alerts")
