"""add_phase6_risk_scoring_fields

Revision ID: 28b6d8f1e002
Revises: 17f75cff89f0
Create Date: 2026-09-06 21:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column


# revision identifiers, used by Alembic.
revision: str = '28b6d8f1e002'
down_revision: Union[str, None] = '17f75cff89f0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update scans table
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('posture_rating', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('risk_summary', sa.JSON(), server_default='{}', nullable=False))

    # 2. Update findings table
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('risk_level', sa.String(length=50), server_default='MEDIUM', nullable=False))
        batch_op.add_column(sa.Column('risk_priority', sa.String(length=50), server_default='MEDIUM', nullable=False))
        batch_op.add_column(sa.Column('risk_factors', sa.JSON(), server_default='{}', nullable=False))
        batch_op.add_column(sa.Column('risk_explanation', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('risk_calculated_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index(batch_op.f('ix_findings_risk_level'), ['risk_level'], unique=False)
        batch_op.create_index(batch_op.f('ix_findings_risk_priority'), ['risk_priority'], unique=False)

    # 3. Deterministic backfill for any existing finding records
    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            UPDATE findings
            SET 
                risk_level = CASE 
                    WHEN risk_score >= 90 THEN 'CRITICAL'
                    WHEN risk_score >= 70 THEN 'HIGH'
                    WHEN risk_score >= 40 THEN 'MEDIUM'
                    WHEN risk_score >= 1 THEN 'LOW'
                    ELSE 'INFO'
                END,
                risk_priority = CASE
                    WHEN risk_score >= 90 THEN 'IMMEDIATE'
                    WHEN risk_score >= 70 THEN 'HIGH'
                    WHEN risk_score >= 40 THEN 'MEDIUM'
                    ELSE 'LOW'
                END,
                risk_explanation = COALESCE(risk_explanation, 'Legacy finding backfilled with baseline severity mapping.')
            WHERE risk_explanation IS NULL OR risk_level = 'MEDIUM'
            """
        )
    )


def downgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_risk_priority'))
        batch_op.drop_index(batch_op.f('ix_findings_risk_level'))
        batch_op.drop_column('risk_calculated_at')
        batch_op.drop_column('risk_explanation')
        batch_op.drop_column('risk_factors')
        batch_op.drop_column('risk_priority')
        batch_op.drop_column('risk_level')

    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('risk_summary')
        batch_op.drop_column('posture_rating')
