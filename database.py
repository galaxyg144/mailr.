import sqlite3
import time
from typing import List, Dict, Optional

DB_NAME = "mailr.sqlite"

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        address TEXT PRIMARY KEY,
        role TEXT,
        public_key TEXT
    )''')
    
    # Messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        recipient TEXT,
        subject TEXT,
        body TEXT,
        timestamp TEXT,
        global_msg BOOLEAN
    )''')
    
    # Challenges table
    c.execute('''CREATE TABLE IF NOT EXISTS challenges (
        address TEXT PRIMARY KEY,
        challenge TEXT,
        expires REAL
    )''')
    
    # Sessions table
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        address TEXT,
        expires REAL
    )''')
    
    conn.commit()
    conn.close()

# -------------------
# User Operations
# -------------------
def add_user(user: dict):
    conn = get_db()
    try:
        conn.execute('INSERT INTO users (address, role, public_key) VALUES (?, ?, ?)',
                     (user['address'], user['role'], user['public_key']))
        conn.commit()
    finally:
        conn.close()

def get_user(address: str) -> Optional[dict]:
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM users WHERE address = ?', (address,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_all_users() -> List[dict]:
    conn = get_db()
    try:
        rows = conn.execute('SELECT * FROM users').fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

# -------------------
# Challenge Operations
# -------------------
def upsert_challenge(address: str, challenge: str, expires: float):
    conn = get_db()
    try:
        conn.execute('INSERT OR REPLACE INTO challenges (address, challenge, expires) VALUES (?, ?, ?)',
                     (address, challenge, expires))
        conn.commit()
    finally:
        conn.close()

def get_challenge(address: str) -> Optional[dict]:
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM challenges WHERE address = ?', (address,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

# -------------------
# Session Operations
# -------------------
def upsert_session(address: str, token: str, expires: float):
    conn = get_db()
    try:
        # Since token is PK, we can just insert (if token is unique new session)
        # But upsert implies we might update? No, token is key.
        # Logic: creating a new session = new token.
        conn.execute('INSERT INTO sessions (token, address, expires) VALUES (?, ?, ?)',
                     (token, address, expires))
        conn.commit()
    finally:
        conn.close()

def get_session(token: str) -> Optional[dict]:
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM sessions WHERE token = ?', (token,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

# -------------------
# Message Operations
# -------------------
def add_message(msg: dict):
    conn = get_db()
    try:
        conn.execute('''
            INSERT INTO messages (sender, recipient, subject, body, timestamp, global_msg)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (msg['sender'], msg['recipient'], msg['subject'], msg['body'], msg['timestamp'], msg.get('global_msg', False)))
        conn.commit()
    finally:
        conn.close()

def get_inbox_messages(address: str, role: str) -> List[dict]:
    conn = get_db()
    try:
        # Replicating logic:
        # 1. Direct messages: recipient == address
        # 2. System/Global messages: recipient startswith "~" AND (role == "$" OR msg.global_msg == True)
        
        # We can try to do this in SQL or fetch relevant candidates and filter.
        # Fetching candidates: recipient = address OR recipient LIKE "~%"
        
        query = '''
            SELECT * FROM messages 
            WHERE recipient = ? 
            OR (recipient LIKE '~%' AND (global_msg = 1 OR ? = '$'))
        '''
        rows = conn.execute(query, (address, role)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
