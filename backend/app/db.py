"""Database setup and schema helpers."""
from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./vpc_sim.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def ensure_schema() -> None:
    """Apply lightweight schema migrations for new columns."""
    with engine.begin() as conn:
        for table, column in [("vpcs", "ipv6_cidr_block"), ("subnets", "ipv6_cidr_block")]:
            info = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            if not any(row[1] == column for row in info):
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR"))
