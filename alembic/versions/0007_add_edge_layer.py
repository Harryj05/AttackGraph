"""Add layer column to edges and backfill asset vs attack layers

Revision ID: 0007_add_edge_layer
Revises: 0006_add_is_synthetic
Create Date: 2026-10-13
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0007_add_edge_layer'
down_revision: Union[str, None] = '0006_add_is_synthetic'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ASSET_RELATIONS = ['has_endpoint', 'runs_service']

def upgrade() -> None:
    # 1. Add column layer to edges
    op.add_column('edges', sa.Column('layer', sa.String(50), nullable=False, server_default='attack'))

    # 2. Backfill asset layer edges
    edges_table = sa.table(
        'edges',
        sa.column('id', sa.String),
        sa.column('relation_type', sa.String),
        sa.column('layer', sa.String)
    )

    op.execute(
        edges_table.update()
        .where(sa.func.lower(edges_table.c.relation_type).in_(ASSET_RELATIONS))
        .values(layer='asset')
    )

    op.execute(
        edges_table.update()
        .where(~sa.func.lower(edges_table.c.relation_type).in_(ASSET_RELATIONS))
        .values(layer='attack')
    )

def downgrade() -> None:
    op.drop_column('edges', 'layer')
