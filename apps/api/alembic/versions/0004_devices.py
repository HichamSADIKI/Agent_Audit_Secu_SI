"""table devices : appareils découverts sur le réseau par le scan d'un agent

Revision ID: 0004_devices
Revises: 0003_alert_open_unique
Create Date: 2026-05-31

"""
from alembic import op
import sqlalchemy as sa

revision = "0004_devices"
down_revision = "0003_alert_open_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("discovered_by_machine_id", sa.Integer(), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("mac", sa.String(length=17), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("device_type", sa.String(length=64), nullable=False),
        sa.Column("os_guess", sa.String(length=128), nullable=True),
        sa.Column("is_gateway", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["discovered_by_machine_id"], ["machines.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "discovered_by_machine_id", "mac", name="uq_devices_machine_mac"
        ),
    )
    op.create_index(
        op.f("ix_devices_discovered_by_machine_id"),
        "devices",
        ["discovered_by_machine_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_devices_discovered_by_machine_id"), table_name="devices"
    )
    op.drop_table("devices")
