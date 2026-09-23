"""add role_arn and external_id to cloud_accounts

Revision ID: 7a8b9c0d1e2f
Revises: 64c8eb5045fe
Create Date: 2026-09-08 15:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7a8b9c0d1e2f'
down_revision: Union[str, None] = '64c8eb5045fe'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('cloud_accounts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role_arn', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('external_id', sa.String(length=100), nullable=True))
        batch_op.create_index('ix_cloud_accounts_external_id', ['external_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('cloud_accounts', schema=None) as batch_op:
        batch_op.drop_index('ix_cloud_accounts_external_id')
        batch_op.drop_column('external_id')
        batch_op.drop_column('role_arn')
