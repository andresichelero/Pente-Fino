"""add_filepath_and_threat_intel

Revision ID: 0003_add_filepath_and_threat_intel
Revises: 0002_add_observations
Create Date: 2026-10-24 13:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0003_add_filepath_and_threat_intel'
down_revision: Union[str, None] = '0002_add_observations'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add file_path to template_catalog
    op.add_column('template_catalog', sa.Column('file_path', sa.Text(), nullable=True))

    # 2. Add threat intel columns to findings
    op.add_column('findings', sa.Column('epss_score', sa.Float(), nullable=True))
    op.add_column('findings', sa.Column('epss_percentile', sa.Float(), nullable=True))
    op.add_column(
        'findings',
        sa.Column('in_cisa_kev', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    )
    op.add_column(
        'findings',
        sa.Column('priority_tier', sa.String(32), server_default=sa.text("'standard'"), nullable=False),
    )

    # 3. Check constraint and indexes
    op.create_check_constraint(
        'chk_findings_priority_tier',
        'findings',
        "priority_tier IN ('critical_kev', 'high_epss', 'elevated', 'standard')",
    )
    op.create_index('ix_findings_priority_tier', 'findings', ['priority_tier'])
    op.create_index('ix_findings_in_cisa_kev', 'findings', ['in_cisa_kev'])


def downgrade() -> None:
    op.drop_index('ix_findings_in_cisa_kev', table_name='findings')
    op.drop_index('ix_findings_priority_tier', table_name='findings')
    op.drop_constraint('chk_findings_priority_tier', 'findings', type_='check')

    op.drop_column('findings', 'priority_tier')
    op.drop_column('findings', 'in_cisa_kev')
    op.drop_column('findings', 'epss_percentile')
    op.drop_column('findings', 'epss_score')

    op.drop_column('template_catalog', 'file_path')
