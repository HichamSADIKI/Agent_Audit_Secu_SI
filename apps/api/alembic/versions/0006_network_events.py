"""table network_events : intrusions & anomalies réseau (Phase C)

Revision ID: 0006_network_events
Revises: 0005_ports_vulns
Create Date: 2026-05-31

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0006_network_events"
down_revision = "0005_ports_vulns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "network_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("machine_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("src_ip", sa.String(length=45), nullable=True),
        sa.Column("dst_ip", sa.String(length=45), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_network_events_machine_id"), "network_events", ["machine_id"], unique=False
    )
    op.create_index(op.f("ix_network_events_kind"), "network_events", ["kind"], unique=False)
    op.create_index(
        op.f("ix_network_events_created_at"), "network_events", ["created_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_network_events_created_at"), table_name="network_events")
    op.drop_index(op.f("ix_network_events_kind"), table_name="network_events")
    op.drop_index(op.f("ix_network_events_machine_id"), table_name="network_events")
    op.drop_table("network_events")
