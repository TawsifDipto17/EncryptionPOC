from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg2 import sql
from db_utils import TARGET_TABLE, KEY_TABLE

def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def decrypt_row_by_id(conn, master_key, target_row_id):
    with conn.cursor() as cur:
        cur.execute(sql.SQL(f"""
            SELECT
                customerid_enc, customeridnonce,
                name_enc, namenonce,
                address_enc, addressnonce,
                email_enc, emailnonce,
                phone_enc, phonennonce,
                age, gender, accounttype, accountbalance, registrationdate
            FROM {TARGET_TABLE}
            WHERE id = %s;
        """), (target_row_id,))
        r = cur.fetchone()
        if not r:
            raise ValueError(f"No row with id {target_row_id}")

        (customerid_enc, customeridnonce,
         name_enc, namenonce,
         address_enc, addressnonce,
         email_enc, emailnonce,
         phone_enc, phonennonce,
         age, gender, accounttype, accountbalance, registrationdate) = r

        cur.execute(sql.SQL(f"""
            SELECT encrypteddatakey, datakeynonce FROM {KEY_TABLE}
            WHERE rowid = %s ORDER BY id DESC LIMIT 1;
        """), (target_row_id,))
        kr = cur.fetchone()
        if not kr:
            raise ValueError(f"No key entry for row {target_row_id}")

        encrypted_dk, dk_nonce = kr
        data_key = aesgcm_decrypt(master_key, dk_nonce, encrypted_dk)

        def dec_col(nonce, ct):
            if nonce is None or ct is None:
                return None
            return aesgcm_decrypt(data_key, nonce, ct).decode("utf-8")

        return {
            "customerid": dec_col(customeridnonce, customerid_enc),
            "name": dec_col(namenonce, name_enc),
            "address": dec_col(addressnonce, address_enc),
            "email": dec_col(emailnonce, email_enc),
            "phonenumber": dec_col(phonennonce, phone_enc),
            "age": age,
            "gender": gender,
            "accounttype": accounttype,
            "accountbalance": accountbalance,
            "registrationdate": registrationdate
        }
