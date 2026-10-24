"""initial_schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-24 04:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Enable pgcrypto extension if on PostgreSQL
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

    # 2. Table: programs
    op.create_table(
        'programs',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('slug', sa.Text(), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('platform', sa.Text(), nullable=False),
        sa.Column('state', sa.Text(), nullable=False),
        sa.Column('default_policy_id', sa.Text(), server_default='bounty-safe', nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("platform IN ('hackerone', 'bugcrowd', 'intigriti', 'private', 'lab')", name='chk_programs_platform'),
        sa.CheckConstraint("state IN ('active', 'suspended', 'archived')", name='chk_programs_state'),
        sa.PrimaryKeyConstraint('id', name='pk_programs'),
        sa.UniqueConstraint('slug', name='uq_programs_slug')
    )
    op.create_index('ix_programs_slug', 'programs', ['slug'])

    # 3. Table: authorization_snapshots
    op.create_table(
        'authorization_snapshots',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('program_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('source_url', sa.Text(), nullable=True),
        sa.Column('policy_hash', sa.CHAR(length=64), nullable=False),
        sa.Column('rules_json', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('valid_from', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('valid_until', sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['program_id'], ['programs.id'], ondelete='RESTRICT', name='fk_auth_snapshots_program_id'),
        sa.PrimaryKeyConstraint('id', name='pk_authorization_snapshots'),
        sa.UniqueConstraint('program_id', 'policy_hash', name='uq_auth_snapshots_program_policy')
    )

    # 4. Table: scope_rules
    op.create_table(
        'scope_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('program_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('priority', sa.Integer(), server_default='100', nullable=False),
        sa.Column('asset_type', sa.Text(), nullable=False),
        sa.Column('pattern', sa.Text(), nullable=False),
        sa.Column('action', sa.Text(), nullable=False),
        sa.Column('allowed_ports', postgresql.ARRAY(sa.Integer()), nullable=True),
        sa.Column('denied_paths', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('max_impact_class', sa.Text(), server_default='safe_read_only', nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("asset_type IN ('domain', 'wildcard_domain', 'hostname', 'url', 'cidr', 'ip')", name='chk_scope_rules_asset_type'),
        sa.CheckConstraint("action IN ('allow', 'deny', 'discover_only')", name='chk_scope_rules_action'),
        sa.CheckConstraint("max_impact_class IN ('passive', 'safe_read_only', 'active_reviewed', 'stateful', 'intrusive', 'lab_only')", name='chk_scope_rules_max_impact'),
        sa.ForeignKeyConstraint(['program_id'], ['programs.id'], ondelete='CASCADE', name='fk_scope_rules_program_id'),
        sa.PrimaryKeyConstraint('id', name='pk_scope_rules')
    )
    op.create_index('ix_scope_rules_prog_priority', 'scope_rules', ['program_id', 'priority'])
    op.create_index('ix_scope_rules_prog_action', 'scope_rules', ['program_id', 'action'])

    # 5. Table: assets
    op.create_table(
        'assets',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('program_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('canonical_key', sa.Text(), nullable=False),
        sa.Column('asset_type', sa.Text(), nullable=False),
        sa.Column('scope_state', sa.Text(), nullable=False),
        sa.Column('first_seen', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_seen', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("scope_state IN ('in_scope_explicit', 'in_scope_derived', 'candidate', 'out_of_scope')", name='chk_assets_scope_state'),
        sa.ForeignKeyConstraint(['program_id'], ['programs.id'], ondelete='CASCADE', name='fk_assets_program_id'),
        sa.PrimaryKeyConstraint('id', name='pk_assets'),
        sa.UniqueConstraint('program_id', 'asset_type', 'canonical_key', name='uq_assets_prog_type_canonical')
    )
    op.create_index('ix_assets_prog_scope_state', 'assets', ['program_id', 'scope_state'])
    op.create_index('ix_assets_canonical_key', 'assets', ['canonical_key'])

    # 6. Table: template_catalog
    op.create_table(
        'template_catalog',
        sa.Column('id', sa.Text(), nullable=False),
        sa.Column('upstream_revision', sa.Text(), nullable=False),
        sa.Column('bundle_hash', sa.CHAR(length=64), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('protocol', sa.Text(), nullable=False),
        sa.Column('http_methods', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('impact_class', sa.Text(), nullable=False),
        sa.Column('cve_id', sa.Text(), nullable=True),
        sa.Column('cwe_id', sa.Text(), nullable=True),
        sa.Column('severity', sa.Text(), nullable=True),
        sa.Column('technologies', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('raw_yaml', sa.Text(), nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("impact_class IN ('passive', 'safe_read_only', 'active_reviewed', 'stateful', 'intrusive', 'lab_only')", name='chk_template_impact_class'),
        sa.PrimaryKeyConstraint('id', name='pk_template_catalog')
    )
    op.create_index('ix_template_catalog_cve_id', 'template_catalog', ['cve_id'])
    op.create_index('ix_template_catalog_impact', 'template_catalog', ['impact_class'])
    op.create_index('ix_template_catalog_protocol', 'template_catalog', ['protocol'])

    # 7. Table: findings
    op.create_table(
        'findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('program_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('dedup_key', sa.CHAR(length=64), nullable=False),
        sa.Column('detector_id', sa.Text(), nullable=False),
        sa.Column('advisory_id', sa.Text(), nullable=True),
        sa.Column('status', sa.Text(), nullable=False),
        sa.Column('evidence_level', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Text(), nullable=False),
        sa.Column('first_seen', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_seen', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("status IN ('candidate', 'validated', 'false_positive', 'reported', 'accepted', 'remediated', 'resolved', 'reopened')", name='chk_findings_status'),
        sa.CheckConstraint("evidence_level IN ('E0', 'E1', 'E2', 'E3')", name='chk_findings_evidence_level'),
        sa.CheckConstraint("confidence IN ('low', 'medium', 'high')", name='chk_findings_confidence'),
        sa.ForeignKeyConstraint(['program_id'], ['programs.id'], ondelete='CASCADE', name='fk_findings_program_id'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE', name='fk_findings_asset_id'),
        sa.ForeignKeyConstraint(['detector_id'], ['template_catalog.id'], ondelete='RESTRICT', name='fk_findings_detector_id'),
        sa.PrimaryKeyConstraint('id', name='pk_findings'),
        sa.UniqueConstraint('program_id', 'dedup_key', name='uq_findings_prog_dedup')
    )
    op.create_index('ix_findings_prog_status', 'findings', ['program_id', 'status'])
    op.create_index('ix_findings_prog_evidence', 'findings', ['program_id', 'evidence_level'])
    op.create_index('ix_findings_asset_id', 'findings', ['asset_id'])

    # 8. Table: evidence
    op.create_table(
        'evidence',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('run_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('evidence_type', sa.Text(), nullable=False),
        sa.Column('original_sha256', sa.CHAR(length=64), nullable=True),
        sa.Column('sanitized_sha256', sa.CHAR(length=64), nullable=False),
        sa.Column('seaweed_object_key', sa.Text(), nullable=False),
        sa.Column('redaction_profile', sa.Text(), server_default='bounty-safe-v1', nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("evidence_type IN ('dns', 'http_interaction', 'tls', 'fingerprint')", name='chk_evidence_type'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE', name='fk_evidence_finding_id'),
        sa.PrimaryKeyConstraint('id', name='pk_evidence')
    )
    op.create_index('ix_evidence_finding_id', 'evidence', ['finding_id'])
    op.create_index('ix_evidence_run_id', 'evidence', ['run_id'])
    op.create_index('ix_evidence_sanitized_sha', 'evidence', ['sanitized_sha256'])

    # 9. Table: audit_events
    op.create_table(
        'audit_events',
        sa.Column('sequence', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('actor', sa.Text(), server_default='system', nullable=False),
        sa.Column('event_type', sa.Text(), nullable=False),
        sa.Column('object_type', sa.Text(), nullable=False),
        sa.Column('object_id', sa.Text(), nullable=False),
        sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('occurred_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('sequence', name='pk_audit_events')
    )
    op.create_index('ix_audit_events_type_time', 'audit_events', ['event_type', 'occurred_at'])
    op.create_index('ix_audit_events_object', 'audit_events', ['object_type', 'object_id'])

    # 10. PostgreSQL trigger function and trigger to prevent audit tampering
    if bind.dialect.name == "postgresql":
        op.execute("""
            CREATE OR REPLACE FUNCTION trg_prevent_audit_tampering()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION 'Table audit_events is append-only: UPDATE and DELETE operations are prohibited.'
                    USING ERRCODE = '23505';
            END;
            $$ LANGUAGE plpgsql;
        """)

        op.execute("""
            CREATE TRIGGER trg_audit_events_immutable
            BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION trg_prevent_audit_tampering();
        """)


def downgrade() -> None:
    bind = op.get_bind()

    # 1. Drop trigger and function if on PostgreSQL
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trg_audit_events_immutable ON audit_events;")
        op.execute("DROP FUNCTION IF EXISTS trg_prevent_audit_tampering();")

    # 2. Drop tables in reverse dependency order
    op.drop_table('audit_events')
    op.drop_table('evidence')
    op.drop_table('findings')
    op.drop_table('template_catalog')
    op.drop_table('assets')
    op.drop_table('scope_rules')
    op.drop_table('authorization_snapshots')
    op.drop_table('programs')
