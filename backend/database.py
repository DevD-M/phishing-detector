from sqlalchemy import create_engine, text
from dotenv import load_dotenv
import os

load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL)


def get_connection():
    return engine.connect()


def init_domain_cache_table():
    """
    Creates the domain_cache table if it doesn't exist.
    Call this once at startup (e.g. from main.py).
    """
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS domain_cache (
                domain TEXT PRIMARY KEY,
                reg_len_feature INTEGER,
                age_feature INTEGER,
                cached_at TIMESTAMP
            )
        """))
        conn.commit()


def init_scans_explanation_column():
    """
    Adds an 'explanation' column to the existing scans table if it doesn't
    already exist, so LLM-generated explanations can be persisted alongside
    each scan. Safe to call every startup — no-ops if the column is already there.
    """
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS explanation TEXT"))
        conn.commit()


def get_cached_domain(domain: str):
    """
    Returns (reg_len_feature, age_feature, cached_at) or None if not cached.
    """
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT reg_len_feature, age_feature, cached_at FROM domain_cache WHERE domain = :domain"),
            {"domain": domain}
        ).fetchone()
        return result


def upsert_cached_domain(domain: str, reg_len_feature: int, age_feature: int, cached_at):
    """
    Inserts or updates a domain's cached WHOIS-derived features.
    """
    with engine.connect() as conn:
        conn.execute(text("""
            INSERT INTO domain_cache (domain, reg_len_feature, age_feature, cached_at)
            VALUES (:domain, :reg_len_feature, :age_feature, :cached_at)
            ON CONFLICT (domain)
            DO UPDATE SET
                reg_len_feature = :reg_len_feature,
                age_feature = :age_feature,
                cached_at = :cached_at
        """), {
            "domain": domain,
            "reg_len_feature": reg_len_feature,
            "age_feature": age_feature,
            "cached_at": cached_at
        })
        conn.commit()
