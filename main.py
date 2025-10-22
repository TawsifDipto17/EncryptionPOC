from db_utils import get_conn, create_target_schema, SOURCE_TABLE
from encrypt_utils import generate_master_key, load_master_key, process_all_rows_encrypt
from decrypt_utils import decrypt_row_by_id
from psycopg2 import sql

def main():
    generate_master_key()
    master_key = load_master_key()

    conn = get_conn()
    try:
        create_target_schema(conn)

        # Original Row For Reference
        with conn.cursor() as cur:
            cur.execute(sql.SQL(f"SELECT * FROM {SOURCE_TABLE} LIMIT 1;"))
            row = cur.fetchone()
            if row:
                cols = [d[0] for d in cur.description]
                print("\n=== ORIGINAL ROW ===")
                print(dict(zip(cols, row)))
            else:
                print("[warn] No rows found.")
                return

        # Encryption
        process_all_rows_encrypt(conn, master_key)

        # Encrypted row example
        with conn.cursor() as cur:
            cur.execute(sql.SQL("SELECT * FROM customers_encrypted WHERE id = 1;"))
            enc_row = cur.fetchone()
            if enc_row:
                cols = [d[0] for d in cur.description]
                print("\n=== ENCRYPTED ROW ===")
                print(dict(zip(cols, enc_row)))

        # Decryption
        print("\n=== DECRYPTED ROW ===")
        try:
            decrypted = decrypt_row_by_id(conn, master_key, 1)
            for k, v in decrypted.items():
                print(f"{k}: {v}")
        except Exception as e:
            print(f"[warn] Could not decrypt: {e}")

    finally:
        conn.close()

if __name__ == "__main__":
    main()
