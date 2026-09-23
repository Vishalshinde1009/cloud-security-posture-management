"""backfill external_id for legacy aws accounts

Revision ID: 8b9c0d1e2f3a
Revises: 7a8b9c0d1e2f
Create Date: 2026-09-08 16:30:00.000000

"""
from typing import Sequence, Union
import secrets
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8b9c0d1e2f3a'
down_revision: Union[str, None] = '7a8b9c0d1e2f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    cloud_accounts = sa.table(
        'cloud_accounts',
        sa.column('id', sa.String),
        sa.column('provider', sa.String),
        sa.column('external_id', sa.String),
    )

    # Fetch existing external_ids to ensure absolute uniqueness
    existing_records = bind.execute(sa.select(cloud_accounts.c.external_id)).fetchall()
    used_ids = {r[0] for r in existing_records if r[0]}

    # Query AWS accounts where external_id is NULL
    legacy_accounts = bind.execute(
        sa.select(cloud_accounts.c.id).where(
            sa.and_(
                cloud_accounts.c.provider == 'AWS',
                cloud_accounts.c.external_id.is_(None),
            )
        )
    ).fetchall()

    for acc in legacy_accounts:
        acc_id = acc[0]
        while True:
            new_ext_id = f"cspm-ext-{secrets.token_hex(12)}"
            if new_ext_id not in used_ids:
                used_ids.add(new_ext_id)
                break

        bind.execute(
            cloud_accounts.update()
            .where(cloud_accounts.c.id == acc_id)
            .values(external_id=new_ext_id)
        )


def downgrade() -> None:
    # Retaining backfilled external_id values on downgrade is safe to avoid data corruption.
    pass
