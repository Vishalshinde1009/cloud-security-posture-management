"""add monitoring and security alerts

Revision ID: 9a1b2c3d4e5f
Revises: 8b9c0d1e2f3a
Create Date: 2026-09-21 18:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a1b2c3d4e5f'
down_revision: Union[str, None] = '8b9c0d1e2f3a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create monitoring_configs table
    op.create_table(
        'monitoring_configs',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('cloud_account_id', sa.Uuid(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('scan_interval_minutes', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['cloud_account_id'], ['cloud_accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cloud_account_id', name='uq_monitoring_configs_cloud_account_id')
    )
    with op.batch_alter_table('monitoring_configs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_monitoring_configs_cloud_account_id'), ['cloud_account_id'], unique=True)

    # 2. Create security_alerts table
    op.create_table(
        'security_alerts',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('cloud_account_id', sa.Uuid(), nullable=False),
        sa.Column('finding_id', sa.Uuid(), nullable=True),
        sa.Column('alert_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('previous_value', sa.String(length=255), nullable=True),
        sa.Column('current_value', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='OPEN'),
        sa.Column('first_detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['cloud_account_id'], ['cloud_accounts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('security_alerts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_security_alerts_cloud_account_id'), ['cloud_account_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_finding_id'), ['finding_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_alert_type'), ['alert_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_security_alerts_status'), ['status'], unique=False)
        batch_op.create_index('ix_security_alerts_account_status', ['cloud_account_id', 'status'], unique=False)
        batch_op.create_index('ix_security_alerts_account_type', ['cloud_account_id', 'alert_type'], unique=False)
        batch_op.create_index('ix_security_alerts_account_finding_type', ['cloud_account_id', 'finding_id', 'alert_type'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('security_alerts', schema=None) as batch_op:
        batch_op.drop_index('ix_security_alerts_account_finding_type')
        batch_op.drop_index('ix_security_alerts_account_type')
        batch_op.drop_index('ix_security_alerts_account_status')
        batch_op.drop_index(batch_op.f('ix_security_alerts_status'))
        batch_op.drop_index(batch_op.f('ix_security_alerts_severity'))
        batch_op.drop_index(batch_op.f('ix_security_alerts_alert_type'))
        batch_op.drop_index(batch_op.f('ix_security_alerts_finding_id'))
        batch_op.drop_index(batch_op.f('ix_security_alerts_cloud_account_id'))
    op.drop_table('security_alerts')

    with op.batch_alter_table('monitoring_configs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_monitoring_configs_cloud_account_id'))
    op.drop_table('monitoring_configs')
