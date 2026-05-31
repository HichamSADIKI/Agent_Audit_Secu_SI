"""tables device_ports + device_vulns : ports ouverts et vulnérabilités (Phase B)

Revision ID: 0005_ports_vulns
Revises: 0004_devices
Create Date: 2026-05-31

"""
from alembic import op
import sqlalchemy as sa

revision = "0005_ports_vulns"
down_revision = "0004_devices"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_ports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("service_name", sa.String(length=64), nullable=True),
        sa.Column("service_version", sa.String(length=128), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "port", "protocol", name="uq_device_port_proto"),
    )
    op.create_index(
        op.f("ix_device_ports_device_id"), "device_ports", ["device_id"], unique=False
    )

    op.create_table(
        "device_vulns",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("port_id", sa.Integer(), nullable=True),
        sa.Column("cve_id", sa.String(length=32), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["port_id"], ["device_ports.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_device_vulns_device_id"), "device_vulns", ["device_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_device_vulns_device_id"), table_name="device_vulns")
    op.drop_table("device_vulns")
    op.drop_index(op.f("ix_device_ports_device_id"), table_name="device_ports")
    op.drop_table("device_ports")
