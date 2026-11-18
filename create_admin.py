import getpass
import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash

db_path = Path(__file__).resolve().parent / "shahzain.db"
username = input("Admin username: ").strip()
password = getpass.getpass("Admin password (12+ characters): ")
if len(username) < 3 or len(password) < 12:
    raise SystemExit("Username kam az kam 3 aur password 12 characters ka hona chahiye.")
db = sqlite3.connect(db_path)
db.execute("""CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)""")
try:
    db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
               (username, generate_password_hash(password)))
    db.commit()
    print("Admin account create ho gaya.")
except sqlite3.IntegrityError:
    print("Ye username pehle se use ho raha hai.")
finally:
    db.close()
