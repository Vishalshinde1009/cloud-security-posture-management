"""add_user_id_to_cloud_accounts

Revision ID: 64c8eb5045fe
Revises: c54e81a3d091
Create Date: 2026-09-08 15:01:29.134964

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '64c8eb5045fe'
down_revision: Union[str, Sequence[str], None] = 'c54e81a3d091'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: Add user_id column with foreign key to cloud_accounts."""
    with op.batch_alter_table('cloud_accounts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.Uuid(), nullable=True))
        batch_op.create_foreign_key('fk_cloud_accounts_user_id_users', 'users', ['user_id'], ['id'], ondelete='SET NULL')
        batch_op.create_index(batch_op.f('ix_cloud_accounts_user_id'), ['user_id'], unique=False)

    # Assign existing cloud accounts to the existing initial ADMIN user if one exists
    conn = op.get_bind()
    admin_res = conn.execute(sa.text("SELECT id FROM users WHERE username = 'admin' LIMIT 1")).fetchone()
    if admin_res:
        admin_id = admin_res[0]
        conn.execute(
            sa.text("UPDATE cloud_accounts SET user_id = :admin_id WHERE user_id IS NULL"),
            {"admin_id": admin_id}
        )


def downgrade() -> None:
    """Downgrade schema: Remove user_id column from cloud_accounts."""
    with op.batch_alter_table('cloud_accounts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_cloud_accounts_user_id'))
        batch_op.drop_constraint('fk_cloud_accounts_user_id_users', type_='foreignkey')
        batch_op.drop_column('user_id')

