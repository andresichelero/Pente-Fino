"""add_observations_table

Revision ID: 0002_add_observations
Revises: 0001_initial_schema
Create Date: 2026-10-24 09:41:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0002_add_observations'
down_revision: Union[str, None] = '0001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'observations',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('observation_type', sa.Text(), nullable=False),
        sa.Column('raw_data', sa.Text(), nullable=True),
        sa.Column('metadata_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], name='fk_observations_asset_id', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name='pk_observations')
    )
    op.create_index('ix_observations_asset_id', 'observations', ['asset_id'], unique=False)
    op.create_index('ix_observations_type', 'observations', ['observation_type'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_observations_type', table_name='observations')
    op.drop_index('ix_observations_asset_id', table_name='observations')
    op.drop_table('observations')
