"""
With API sqlite3
Database Schema Module
Defines database tables and provides database initialization.
"""

import sqlite3
from typing import Optional

DATABASE_PATH = 'banking.db'

def get_db_connection():
    """
    Create a database connection.
    
    Returns:
        sqlite3.Connection object
        
    Note:
        In production, use connection pooling (e.g., SQLAlchemy)
    """
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row          # Access columns by name
    return conn


def init_database():
    """
    Initialize database with all required tables.
    
    Tables:
        - users: User accounts with hashed passwords
        - accounts: Bank accounts linked to users
        - transactions: Legacy plaintext demo transaction history
        - secure_transactions: Encrypted payload store (diagram-aligned)
        - session_audit: Session lifecycle log
        - audit_events: Security/audit event log
    
    Security Features:
        - Password stored as hash (bcrypt), never plaintext
        - Unique nonce per transaction (prevents replay attacks)
        - Foreign key constraints for data integrity
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            account_locked BOOLEAN DEFAULT 0
        )
    ''')
    
    # Accounts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            balance REAL DEFAULT 0.00,
            account_type TEXT DEFAULT 'checking',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Transactions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_account TEXT NOT NULL,
            to_account TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            nonce TEXT UNIQUE NOT NULL,
            csrf_token TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'completed',
            FOREIGN KEY (from_account) REFERENCES accounts(account_number),
            FOREIGN KEY (to_account) REFERENCES accounts(account_number)
        )
    ''')
    
    # Secure transactions table (encrypted payload only)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secure_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER NOT NULL,
            key_id TEXT NOT NULL,
            nonce TEXT UNIQUE NOT NULL,
            aad TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            auth_tag TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            risk_decision TEXT DEFAULT 'allow',
            risk_reason TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_user_id) REFERENCES users(id)
        )
    ''')

    # Session audit log
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS session_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Security audit events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL,
            actor_user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_user_id) REFERENCES users(id)
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions(from_account)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions(to_account)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_nonce ON transactions(nonce)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_secure_tx_actor ON secure_transactions(actor_user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_secure_tx_created_at ON secure_transactions(created_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type)')

    # Keep tests deterministic across repeated runs.
    cursor.execute("DELETE FROM transactions WHERE nonce = 'test_nonce_123'")
    
    conn.commit()
    conn.close()
    
    print("Database initialized successfully")


def seed_demo_users():
    """
    Create demo users for testing.
    
    Creates:
        - alice (password: Alice123!) with $5000 balance
        - bob (password: Bob123!) with $3000 balance
    """
    from app.security.passwords import hash_password
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # User: alice
        alice_hash = hash_password('Alice123!')
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            ('alice', alice_hash, 'alice@securebank.com')
        )
        alice_id = cursor.lastrowid
        
        cursor.execute(
            "INSERT INTO accounts (user_id, account_number, balance) VALUES (?, ?, ?)",
            (alice_id, 'ACC001', 5000.00)
        )
        
        # User: bob
        bob_hash = hash_password('Bob123!')
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            ('bob', bob_hash, 'bob@securebank.com')
        )
        bob_id = cursor.lastrowid
        
        cursor.execute(
            "INSERT INTO accounts (user_id, account_number, balance) VALUES (?, ?, ?)",
            (bob_id, 'ACC002', 3000.00)
        )
        
        conn.commit()
        print("Demo users created:")
        print("  - alice / Alice123! (Balance: $5000)")
        print("  - bob / Bob123! (Balance: $3000)")
        
    except sqlite3.IntegrityError:
        print("Demo users already exist")
    finally:
        conn.close()


# Data access functions

def get_user_by_username(username: str) -> Optional[dict]:
    """
    Retrieve user by username.
    
    Args:
        username: Username to lookup
        
    Returns:
        Dictionary with user data, or None if not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, username, password_hash, email, account_locked FROM users WHERE username = ?",
        (username,)
    )
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            'id': row['id'],
            'username': row['username'],
            'password_hash': row['password_hash'],
            'email': row['email'],
            'account_locked': bool(row['account_locked'])
        }
    return None


def get_account_by_user_id(user_id: int) -> Optional[dict]:
    """
    Get bank account for a user.
    
    Args:
        user_id: User's database ID
        
    Returns:
        Dictionary with account data, or None if not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, account_number, balance, account_type FROM accounts WHERE user_id = ?",
        (user_id,)
    )
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            'id': row['id'],
            'account_number': row['account_number'],
            'balance': row['balance'],
            'account_type': row['account_type']
        }
    return None


def get_account_by_number(account_number: str) -> Optional[dict]:
    """
    Get account by account number.
    
    Args:
        account_number: Account number
        
    Returns:
        Dictionary with account data, or None if not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, user_id, account_number, balance FROM accounts WHERE account_number = ?",
        (account_number,)
    )
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            'id': row['id'],
            'user_id': row['user_id'],
            'account_number': row['account_number'],
            'balance': row['balance']
        }
    return None


def update_last_login(user_id: int):
    """
    Update user's last login timestamp.
    
    Args:
        user_id: User's database ID
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
        (user_id,)
    )
    
    conn.commit()
    conn.close()


def log_session_event(user_id: int, event_type: str, ip_address: str = None, user_agent: str = None):
    """
    Log session-related security events.
    
    Args:
        user_id: User's database ID
        event_type: Type of event ('login', 'logout', 'timeout', etc.)
        ip_address: Client IP address
        user_agent: Client user agent string
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO session_audit (user_id, event_type, ip_address, user_agent) VALUES (?, ?, ?, ?)",
        (user_id, event_type, ip_address, user_agent)
    )
    
    conn.commit()
    conn.close()


def get_all_accounts_except(exclude_user_id: int) -> list[dict]:
    """
    Get all accounts except for specified user (for transfer recipient list).
    
    Args:
        exclude_user_id: User ID to exclude
        
    Returns:
        List of account dictionaries
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT account_number, user_id FROM accounts WHERE user_id != ?",
        (exclude_user_id,)
    )
    
    rows = cursor.fetchall()
    conn.close()
    
    return [{'account_number': row['account_number'], 'user_id': row['user_id']} for row in rows]


def get_transaction_history(account_number: str, limit: int = 10) -> list[dict]:
    """
    Get recent transaction history for an account.
    
    Args:
        account_number: Account number
        limit: Maximum number of transactions to return
        
    Returns:
        List of transaction dictionaries
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, from_account, to_account, amount, description, timestamp, status
        FROM transactions
        WHERE from_account = ? OR to_account = ?
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (account_number, account_number, limit))
    
    rows = cursor.fetchall()
    conn.close()
    
    transactions = []
    for row in rows:
        transactions.append({
            'id': row['id'],
            'from_account': row['from_account'],
            'to_account': row['to_account'],
            'amount': row['amount'],
            'description': row['description'],
            'timestamp': row['timestamp'],
            'status': row['status']
        })
    
    return transactions


def count_recent_secure_transactions(actor_user_id: int, window_minutes: int = 5) -> int:
    """
    Count recent secure transactions for velocity/risk checks.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.execute("PRAGMA journal_mode = WAL")
    cursor.execute(
        """
        SELECT COUNT(*) AS tx_count
        FROM secure_transactions
        WHERE actor_user_id = ?
          AND created_at >= datetime('now', ?)
        """,
        (actor_user_id, f"-{int(window_minutes)} minutes"),
    )
    count = int(cursor.fetchone()["tx_count"])
    conn.close()
    return count


def get_secure_transaction_history(actor_user_id: int, limit: int = 10) -> list[dict]:
    """
    Return secure transaction metadata without plaintext financial payload.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, key_id, nonce, status, risk_score, risk_decision, risk_reason, created_at
        FROM secure_transactions
        WHERE actor_user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (actor_user_id, limit),
    )
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row["id"],
            "key_id": row["key_id"],
            "nonce": row["nonce"],
            "status": row["status"],
            "risk_score": row["risk_score"],
            "risk_decision": row["risk_decision"],
            "risk_reason": row["risk_reason"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
