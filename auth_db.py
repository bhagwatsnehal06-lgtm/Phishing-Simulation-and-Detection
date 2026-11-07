import sqlite3
from pathlib import Path
import bcrypt

DB_PATH = Path(__file__).with_name("cyberrisk.db")


def initialize_database():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash BLOB NOT NULL
            )
        """)
        
        # Add role column if it does not already exist
        columns = [
            row[1] for row in
            conn.execute("PRAGMA table_info(users)").fetchall()
        ]

        if "role" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'"
            )

        # Assign Admin role to the selected account
        conn.execute(
            "UPDATE users SET role = 'admin' WHERE email = ?",
            ("abc123@gmail.com",)
        )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                business_name TEXT NOT NULL,
                industry TEXT NOT NULL,
                business_size TEXT NOT NULL,
                threat TEXT NOT NULL,
                description TEXT,
                asset TEXT,
                likelihood INTEGER NOT NULL,
                impact INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)


def register_user(name, email, password):
    name, email = name.strip(), email.strip().lower()
    if not name or not email or not password:
        return False, "Complete all fields."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, hashed)
            )
        return True, "Account created. Please log in."
    except sqlite3.IntegrityError:
        return False, "This email is already registered."


def authenticate_user(email, password):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, name, email, password_hash, role FROM users WHERE email = ?",
            (email.strip().lower(),)
        ).fetchone()

    if row and bcrypt.checkpw(password.encode(), row[3]):
        return {
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "role": row[4]
        }

    return None



def save_assessment(user_id, business_name, industry, business_size, risk):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO assessments
            (user_id, business_name, industry, business_size, threat,
             description, asset, likelihood, impact)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id, business_name, industry, business_size,
            risk["Threat"], risk["Description"], risk["Asset"],
            risk["Likelihood"], risk["Impact"]
        ))


def load_assessments(user_id):
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("""
            SELECT threat, description, asset, likelihood, impact
            FROM assessments WHERE user_id = ? ORDER BY id DESC
        """, (user_id,)).fetchall()
    return [
        {"Threat": r[0], "Description": r[1] or "", "Asset": r[2] or "",
         "Likelihood": r[3], "Impact": r[4]}
        for r in rows
    ]

def load_admin_data():
    with sqlite3.connect(DB_PATH) as conn:

        users = conn.execute("""
            SELECT id, name, email, role
            FROM users
            ORDER BY id DESC
        """).fetchall()

        assessments = conn.execute("""
            SELECT users.name, assessments.business_name,
                   assessments.industry, assessments.threat,
                   assessments.likelihood, assessments.impact
            FROM assessments
            JOIN users ON assessments.user_id = users.id
            ORDER BY assessments.id DESC
        """).fetchall()

    return users, assessments

def update_user_role(user_id, new_role):
    if new_role not in ("admin", "user"):
        return False

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (new_role, user_id)
        )

    return True
def update_user_role(email, new_role):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET role = ? WHERE email = ?",
            (new_role, email.strip().lower())
        )