# PostgreSQL AES-256-GCM Encryption POC

## Overview
This Proof of Concept (POC) demonstrates **envelope encryption** in PostgreSQL using **AES-256-GCM**.

Each row in the dataset gets:
- A unique **data key** (AES-256)
- That data key is encrypted with a **master key**
- The master key is stored **locally** (simulating a simple KMS)

### Flow:
1. Fetch rows from the source table (`customers`)
2. Encrypt sensitive columns and store in target table (`customers_encrypted`)
3. Encrypt the per-row data key and store in a key table (`encryptedkeys`)
4. Decrypt a specific row using the master key

---

## Project Structure
db_utils.py # Database setup, schema creation, date parsing \
encrypt_utils.py # Master key management + encryption logic \
decrypt_utils.py # Decryption logic \
main.py # Entry point - runs the demo end-to-end \
requirements.txt # Dependencies 


---

## Requirements
- Python 3.8+
- PostgreSQL server running locally
- A `Banking` database with a `customers` table containing sample data.

Example table schema (for testing):

```sql
CREATE TABLE customers (
    customerid INT PRIMARY KEY,
    name TEXT,
    address TEXT,
    email TEXT,
    phonenumber TEXT,
    age INT,
    gender TEXT,
    accounttype TEXT,
    accountbalance NUMERIC,
    registrationdate DATE
);


INSERT INTO customers VALUES
(1, 'Alice Tan', '123 Orchard Rd', 'alice@example.com', '91234567', 29, 'Female', 'Savings', 5000.75, '2023-09-12');
```

---

## Quick Start Commands

```bash
# 1. Clone or copy the folder
cd encryption_poc

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run PostgreSQL and ensure your DB connection details in db_utils.py are correct

# 4. Run the main demo
python main.py





