import os
import pymysql
from dotenv import load_dotenv

# Load env variables
load_dotenv()

host = os.getenv("MYSQL_HOST", "127.0.0.1")
port = int(os.getenv("MYSQL_PORT", 3306))
user = os.getenv("MYSQL_USER", "root")
password = os.getenv("MYSQL_PASSWORD", "")
db_name = os.getenv("MYSQL_DB", "forensys")

def init_db():
    print(f"Connecting to MySQL server at {host}:{port} as user '{user}'...")
    # First connect without DB to create it if not exists
    conn = pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        autocommit=True
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
            print(f"Database '{db_name}' created or already exists.")
    finally:
        conn.close()

    # Now connect to the database to create the table
    conn = pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db_name,
        autocommit=True
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(255) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    salt VARCHAR(64) NOT NULL,
                    role VARCHAR(50) NOT NULL,
                    department VARCHAR(255) NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    permissions TEXT NOT NULL
                )
            """)
            print("Table 'users' created or already exists.")
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
