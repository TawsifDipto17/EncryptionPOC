import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg2 import sql
from db_utils import TARGET_TABLE, KEY_TABLE, SOURCE_TABLE, parse_date

MASTER_KEY_PATH = "master.key"

def generate_master_key(path=MASTER_KEY_PATH):
    if os.path.exists(path):
        print(f"[info] Master key already exists at {path}")
        return
    mk = os.urandom(32) # MasterKey Generation Logic, Default to random key generation
    with open(path, "wb") as f:
        f.write(base64.b64encode(mk))
    print(f"[info] Master key generated and saved to {path}")

def load_master_key(path=MASTER_KEY_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Master key file not found: {path}")
    with open(path, "rb") as f:
        mk = base64.b64decode(f.read())
    if len(mk) != 32:
        raise ValueError("Master key must be 32 bytes after decoding.")
    return mk

def aesgcm_encrypt(key: bytes, plaintext: bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) # DataKey Generation Logic
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def process_all_rows_encrypt(conn, master_key):
    with conn.cursor() as cur_src, conn.cursor() as cur_tgt:
        cur_src.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(SOURCE_TABLE)))
        rows = cur_src.fetchall()
        colnames = [desc[0] for desc in cur_src.description]
        print(f"[info] Found {len(rows)} rows in '{SOURCE_TABLE}'.")

        for r in rows:
            row = dict(zip(colnames, r))
            data_key = os.urandom(32)

            def enc_col(val):
                if val is None:
                    return None, None
                val_bytes = str(val).encode()
                nonce, ct = aesgcm_encrypt(data_key, val_bytes)
                return nonce, ct

            cust_nonce, cust_ct = enc_col(row.get("customerid"))
            name_nonce, name_ct = enc_col(row.get("name"))
            addr_nonce, addr_ct = enc_col(row.get("address"))
            email_nonce, email_ct = enc_col(row.get("email"))
            phone_nonce, phone_ct = enc_col(row.get("phonenumber"))

            insert_q = sql.SQL(f"""
                INSERT INTO {TARGET_TABLE} (
                    customerid_enc, customeridnonce,
                    name_enc, namenonce,
                    address_enc, addressnonce,
                    email_enc, emailnonce,
                    phone_enc, phonennonce,
                    age, gender, accounttype, accountbalance, registrationdate
                )
                VALUES (
                    %(customerid_enc)s, %(customeridnonce)s,
                    %(name_enc)s, %(namenonce)s,
                    %(address_enc)s, %(addressnonce)s,
                    %(email_enc)s, %(emailnonce)s,
                    %(phone_enc)s, %(phonennonce)s,
                    %(age)s, %(gender)s, %(accounttype)s, %(accountbalance)s, %(registrationdate)s
                )
                RETURNING id;
            """)

            params = {
                "customerid_enc": cust_ct, "customeridnonce": cust_nonce,
                "name_enc": name_ct, "namenonce": name_nonce,
                "address_enc": addr_ct, "addressnonce": addr_nonce,
                "email_enc": email_ct, "emailnonce": email_nonce,
                "phone_enc": phone_ct, "phonennonce": phone_nonce,
                "age": row.get("age"),
                "gender": row.get("gender"),
                "accounttype": row.get("accounttype"),
                "accountbalance": row.get("accountbalance"),
                "registrationdate": parse_date(row.get("registrationdate"))
            }
            cur_tgt.execute(insert_q, params)
            tgt_row_id = cur_tgt.fetchone()[0]

            dk_nonce, dk_ct = aesgcm_encrypt(master_key, data_key)
            cur_tgt.execute(sql.SQL(f"""
                INSERT INTO {KEY_TABLE} (rowid, encrypteddatakey, datakeynonce)
                VALUES (%s, %s, %s);
            """), (tgt_row_id, dk_ct, dk_nonce))

            conn.commit()
            print(f"[info] Encrypted row -> target id {tgt_row_id}")

