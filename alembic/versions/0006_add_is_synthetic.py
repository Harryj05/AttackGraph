"""Add is_synthetic flag to nodes, edges, and evidence, and tag constructed rows

Revision ID: 0006_add_is_synthetic
Revises: 0005_pattern_stats
Create Date: 2026-10-12
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0006_add_is_synthetic'
down_revision: Union[str, None] = '0005_pattern_stats'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Approved synthetic IDs
SYNTHETIC_NODE_IDS = [
    'n-cred1',
    'n-cred2',
    'n-admin',
    'n-data',
    'f9edc133-c6bb-4d3c-b76a-6151796c0203',
    '81fe00db-9d99-4b3e-b0cc-8ef5b09fd5d1',
    '4bff59ed-73d9-44e7-bd0a-722234b7d79d',
]

SYNTHETIC_EDGE_IDS = [
    'e-cred1-admin',
    'e-cred2-admin',
    'e-admin-data',
    '51a7859e-f7b7-45af-b8dc-4e153e6e1a33',
    '94a6623e-d4c3-4529-ab22-804f371bdb79',
]

SYNTHETIC_EVIDENCE_IDS = [
    'ce88ce37-dac2-492a-8b25-4e631735db7a',
    '29a20cee-7431-460d-84a9-d53c329ce758',
    '3dd337a0-a879-4201-8e56-a49700a43625',
]

def upgrade() -> None:
    # 1. Add column is_synthetic to nodes
    op.add_column('nodes', sa.Column('is_synthetic', sa.Boolean(), nullable=False, server_default=sa.text('false')))

    # 2. Add column is_synthetic to edges
    op.add_column('edges', sa.Column('is_synthetic', sa.Boolean(), nullable=False, server_default=sa.text('false')))

    # 3. Add column is_synthetic to evidence
    op.add_column('evidence', sa.Column('is_synthetic', sa.Boolean(), nullable=False, server_default=sa.text('false')))

    # 4. Tag approved synthetic nodes
    nodes_table = sa.table(
        'nodes',
        sa.column('id', sa.String),
        sa.column('is_synthetic', sa.Boolean)
    )
    op.execute(
        nodes_table.update()
        .where(nodes_table.c.id.in_(SYNTHETIC_NODE_IDS))
        .values(is_synthetic=True)
    )

    # 5. Tag approved synthetic edges
    edges_table = sa.table(
        'edges',
        sa.column('id', sa.String),
        sa.column('is_synthetic', sa.Boolean)
    )
    op.execute(
        edges_table.update()
        .where(edges_table.c.id.in_(SYNTHETIC_EDGE_IDS))
        .values(is_synthetic=True)
    )

    # 6. Tag approved synthetic evidence
    evidence_table = sa.table(
        'evidence',
        sa.column('id', sa.String),
        sa.column('is_synthetic', sa.Boolean)
    )
    op.execute(
        evidence_table.update()
        .where(evidence_table.c.id.in_(SYNTHETIC_EVIDENCE_IDS))
        .values(is_synthetic=True)
    )

def downgrade() -> None:
    op.drop_column('evidence', 'is_synthetic')
    op.drop_column('edges', 'is_synthetic')
    op.drop_column('nodes', 'is_synthetic')
