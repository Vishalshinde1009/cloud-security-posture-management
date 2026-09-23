"""add_finding_notes_table

Revision ID: c54e81a3d091
Revises: 28b6d8f1e002
Create Date: 2026-09-06 22:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c54e81a3d091'
down_revision: Union[str, None] = '28b6d8f1e002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'finding_notes',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('finding_id', sa.Uuid(), nullable=False),
        sa.Column('author_id', sa.Uuid(), nullable=True),
        sa.Column('author_username', sa.String(length=100), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['author_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('finding_notes', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_finding_notes_finding_id'), ['finding_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_finding_notes_author_id'), ['author_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('finding_notes', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_finding_notes_author_id'))
        batch_op.drop_index(batch_op.f('ix_finding_notes_finding_id'))
    op.drop_table('finding_notes')
