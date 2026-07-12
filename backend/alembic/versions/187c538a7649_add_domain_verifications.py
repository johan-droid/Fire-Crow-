"""add_domain_verifications

Revision ID: 187c538a7649
Revises: 8f7e6d5c4b3a
Create Date: 2026-07-05 23:54:05.942463

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '187c538a7649'
down_revision: Union[str, Sequence[str], None] = '8f7e6d5c4b3a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if 'domain_verifications' not in tables:
        op.create_table('domain_verifications',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('domain', sa.String(length=512), nullable=False),
        sa.Column('verification_token', sa.String(length=255), nullable=False),
        sa.Column('verified', sa.Boolean(), nullable=False),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_domain_verifications_domain'), 'domain_verifications', ['domain'], unique=False)
        op.create_index(op.f('ix_domain_verifications_tenant_id'), 'domain_verifications', ['tenant_id'], unique=False)
        op.create_index(op.f('ix_domain_verifications_user_id'), 'domain_verifications', ['user_id'], unique=False)
    else:
        try:
            indexes = [idx['name'] for idx in inspector.get_indexes('domain_verifications')]
        except Exception:
            indexes = []
        for idx in ['ix_domain_verifications_domain', 'ix_domain_verifications_tenant_id', 'ix_domain_verifications_user_id']:
            if idx not in indexes:
                col = idx.split('_')[-1]
                op.create_index(op.f(idx), 'domain_verifications', [col], unique=False)

    if 'audit_jobs' in tables:
        columns = {column["name"] for column in inspector.get_columns("audit_jobs")}
        if 'auto_push' in columns:
            op.drop_column('audit_jobs', 'auto_push')

    if 'users' in tables:
        columns = {column["name"] for column in inspector.get_columns("users")}
        try:
            indexes = [idx['name'] for idx in inspector.get_indexes('users')]
        except Exception:
            indexes = []
        if 'ix_users_email_lower_unique' in indexes:
            op.drop_index(op.f('ix_users_email_lower_unique'), table_name='users', postgresql_where='(email IS NOT NULL)')
        if 'auto_email_reports' in columns:
            op.drop_column('users', 'auto_email_reports')


def downgrade() -> None:
    """Downgrade schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if 'users' in tables:
        columns = {column["name"] for column in inspector.get_columns("users")}
        if 'auto_email_reports' not in columns:
            op.add_column('users', sa.Column('auto_email_reports', sa.BOOLEAN(), server_default=sa.text('true'), autoincrement=False, nullable=True))
        try:
            indexes = [idx['name'] for idx in inspector.get_indexes('users')]
        except Exception:
            indexes = []
        if 'ix_users_email_lower_unique' not in indexes:
            op.create_index(op.f('ix_users_email_lower_unique'), 'users', [sa.literal_column('lower(email::text)')], unique=True, postgresql_where='(email IS NOT NULL)')

    if 'audit_jobs' in tables:
        columns = {column["name"] for column in inspector.get_columns("audit_jobs")}
        if 'auto_push' not in columns:
            op.add_column('audit_jobs', sa.Column('auto_push', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=False))

    if 'domain_verifications' in tables:
        try:
            indexes = [idx['name'] for idx in inspector.get_indexes('domain_verifications')]
        except Exception:
            indexes = []
        for idx in ['ix_domain_verifications_user_id', 'ix_domain_verifications_tenant_id', 'ix_domain_verifications_domain']:
            if idx in indexes:
                op.drop_index(op.f(idx), table_name='domain_verifications')
        op.drop_table('domain_verifications')
