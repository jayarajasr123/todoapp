"""create phone number for user col

Revision ID: 023b24a5c14d
Revises: 
Create Date: 2023-07-15 18:18:40.454872

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '023b24a5c14d'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users',sa.Column('phone_number', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('users','phone_number')
