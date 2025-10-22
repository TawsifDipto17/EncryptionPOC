import os
import psycopg2
from psycopg2 import sql
from datetime import datetime

# Specify the Database Config and Table names
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "Banking",
    "user": "postgres",
    "password": "123"
}

SOURCE_TABLE = "customers"
TARGET_TABLE = "customers_encrypted"
KEY_TABLE = "encrypted_keys"

def get_conn():
    return psycopg2.connect(**DB_CONFIG)

def create_target_schema(conn):
    """Create encrypted and key tables."""
    with conn.cursor() as cur:
        cur.execute(sql.SQL(f"""
            CREATE TABLE IF NOT EXISTS {TARGET_TABLE} (
                id SERIAL PRIMARY KEY,
                customerid_enc BYTEA, customeridnonce BYTEA,
                name_enc BYTEA, namenonce BYTEA,
                address_enc BYTEA, addressnonce BYTEA,
                email_enc BYTEA, emailnonce BYTEA,
                phone_enc BYTEA, phonennonce BYTEA,
                age INTEGER,
                gender TEXT,
                accounttype TEXT,
                accountbalance NUMERIC,
                registrationdate DATE
            );
        """))

        cur.execute(sql.SQL(f"""
            CREATE TABLE IF NOT EXISTS {KEY_TABLE} (
                id SERIAL PRIMARY KEY,
                rowid INTEGER REFERENCES {TARGET_TABLE}(id) ON DELETE CASCADE,
                encrypteddatakey BYTEA,
                datakeynonce BYTEA,
                createdat TIMESTAMP DEFAULT now()
            );
        """))
    conn.commit()
    print("[info] Target tables created or verified.")

def parse_date(val):
    """Safely parse date formats."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.date()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y"):
        try:
            return datetime.strptime(str(val), fmt).date()
        except Exception:
            continue
    return val
