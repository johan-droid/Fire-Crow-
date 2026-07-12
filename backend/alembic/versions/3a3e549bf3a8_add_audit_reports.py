"""add_audit_reports

Revision ID: 3a3e549bf3a8
Revises: d8a7f2b0c1aa
Create Date: 2026-06-08 19:52:55.409325

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3a3e549bf3a8'
down_revision: Union[str, Sequence[str], None] = 'd8a7f2b0c1aa'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if 'audit_reports' not in tables:
        op.create_table('audit_reports',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('job_id', sa.String(length=36), nullable=False),
        sa.Column('html_content', sa.String(), nullable=True),
        sa.Column('markdown_content', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['job_id'], ['audit_jobs.id'], ),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_audit_reports_job_id'), 'audit_reports', ['job_id'], unique=False)
    else:
        # If table exists, double check if index exists
        try:
            indexes = [idx['name'] for idx in inspector.get_indexes('audit_reports')]
        except Exception:
            indexes = []
        if op.f('ix_audit_reports_job_id') not in indexes and 'ix_audit_reports_job_id' not in indexes:
            op.create_index(op.f('ix_audit_reports_job_id'), 'audit_reports', ['job_id'], unique=False)

    if 'audit_jobs' in tables:
        columns = {column["name"] for column in inspector.get_columns("audit_jobs")}
        if 'report_id' not in columns:
            op.add_column('audit_jobs', sa.Column('report_id', sa.String(length=36), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if 'audit_jobs' in tables:
        columns = {column["name"] for column in inspector.get_columns("audit_jobs")}
        if 'report_id' in columns:
            op.drop_column('audit_jobs', 'report_id')

    if 'audit_reports' in tables:
        try:
            indexes = [idx['name'] for idx in inspector.get_indexes('audit_reports')]
        except Exception:
            indexes = []
        if op.f('ix_audit_reports_job_id') in indexes or 'ix_audit_reports_job_id' in indexes:
            op.drop_index(op.f('ix_audit_reports_job_id'), table_name='audit_reports')
        op.drop_table('audit_reports')
