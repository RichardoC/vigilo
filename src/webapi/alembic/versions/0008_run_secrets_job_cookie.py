"""run_secrets table + jobs.target_credential_id

* ``run_secrets``: per-run encrypted secret record redeemed just in time by the
  worker (replaces the old on-disk push-token file).
* ``jobs.target_credential_id``: optional cookie_header credential for
  authenticated white-box testing.

Portable + idempotent via the inspector (migration 0003 may already have created
both from the current models on a fresh database).

Revision ID: 0008_run_secrets_job_cookie
"""
import sqlalchemy as sa
from alembic import op

revision = "0008_run_secrets_job_cookie"  # <=32 chars
down_revision = "0007_job_notify_email"
branch_labels = None
depends_on = None


def _insp():
    return sa.inspect(op.get_bind())


def upgrade() -> None:
    insp = _insp()
    if "run_secrets" not in insp.get_table_names():
        op.create_table(
            "run_secrets",
            sa.Column("run_id", sa.Uuid(), sa.ForeignKey("runs.id", ondelete="CASCADE"),
                      primary_key=True),
            sa.Column("key_hash", sa.String(64), nullable=False),
            sa.Column("secret_enc", sa.LargeBinary(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("redeem_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_redeemed_at", sa.DateTime(timezone=True), nullable=True),
        )
    cols = {c["name"] for c in _insp().get_columns("jobs")}
    if "target_credential_id" not in cols:
        with op.batch_alter_table("jobs") as batch:
            batch.add_column(sa.Column("target_credential_id", sa.Uuid(), nullable=True))
            batch.create_foreign_key(
                "fk_jobs_target_credential", "credentials", ["target_credential_id"], ["id"]
            )


def downgrade() -> None:
    insp = _insp()
    if "target_credential_id" in {c["name"] for c in insp.get_columns("jobs")}:
        with op.batch_alter_table("jobs") as batch:
            batch.drop_column("target_credential_id")
    if "run_secrets" in insp.get_table_names():
        op.drop_table("run_secrets")
