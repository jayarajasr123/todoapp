"""create address_id to users

Revision ID: d41a496d75be
Revises: a41c8e898bd1
Create Date: 2023-07-15 18:57:43.375822

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd41a496d75be'
down_revision = 'a41c8e898bd1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users',sa.Column('address_id',sa.Integer(),nullable=True))
    op.create_foreign_key('address_users_fk',source_table="users",referent_table="address",
                          local_cols=["address_id"], remote_cols=["id"], ondelete="CASCADE")


def downgrade() -> None:
    op.drop_constraint('address_users_fk',table_name="users")
    op.drop_column('users','address_id')
