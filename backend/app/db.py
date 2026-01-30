"""Database setup and schema helpers."""
from __future__ import annotations

import os

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vpc_sim.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@event.listens_for(engine, "connect")
def _configure_sqlite(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()


def ensure_schema() -> None:
    """Apply lightweight schema migrations for new columns."""
    with engine.begin() as conn:
        for table, column in [
            ("vpcs", "ipv6_cidr_block"),
            ("vpcs", "ipv6_association_id"),
            ("vpcs", "dhcp_options_id"),
            ("vpcs", "enable_dns_support"),
            ("vpcs", "enable_dns_hostnames"),
            ("vpcs", "enable_network_address_usage_metrics"),
            ("subnets", "ipv6_cidr_block"),
            ("subnets", "ipv6_association_id"),
            ("subnets", "assign_ipv6_address_on_creation"),
        ]:
            info = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            if not any(row[1] == column for row in info):
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR"))
