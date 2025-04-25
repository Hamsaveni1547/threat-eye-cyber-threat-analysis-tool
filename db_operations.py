import sqlite3
import hashlib
from datetime import datetime

def connect_db():
    """Connect to the database and return connection and cursor"""
    conn = sqlite3.connect('cybersecurity.db')
    conn.row_factory = sqlite3.Row  # This lets us access columns by name
    cursor = conn.cursor()
    return conn, cursor

def hash_password(password):
    """Simple password hashing (in a real app, use more secure methods like bcrypt)"""
    return hashlib.sha256(password.encode()).hexdigest()

# User Management Functions
def add_user(username, password):
    """Add a new user to the database"""
    conn, cursor = connect_db()
    hashed_password = hash_password(password)
    
    try:
        cursor.execute(
            "INSERT INTO User (username, password) VALUES (?, ?)",
            (username, hashed_password)
        )
        conn.commit()
        user_id = cursor.lastrowid
        print(f"User {username} added successfully with ID {user_id}")
        return user_id
    except sqlite3.IntegrityError:
        print(f"Username {username} already exists!")
        return None
    finally:
        conn.close()

def verify_user(username, password):
    """Verify user credentials"""
    conn, cursor = connect_db()
    hashed_password = hash_password(password)
    
    cursor.execute(
        "SELECT user_id FROM User WHERE username = ? AND password = ?",
        (username, hashed_password)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return user['user_id']
    else:
        return None

# Activity Tracking Functions
def record_url_scan(user_id, url, scan_type):
    """Record a URL scan activity for a user"""
    conn, cursor = connect_db()
    
    cursor.execute(
        "INSERT INTO UserActivities (user_id, url, scan_type) VALUES (?, ?, ?)",
        (user_id, url, scan_type)
    )
    conn.commit()
    activity_id = cursor.lastrowid
    conn.close()
    
    print(f"URL scan recorded with ID {activity_id}")
    return activity_id

def get_user_activities(user_id):
    """Get all activities for a specific user"""
    conn, cursor = connect_db()
    
    cursor.execute(
        "SELECT * FROM UserActivities WHERE user_id = ? ORDER BY scan_date DESC",
        (user_id,)
    )
    activities = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return activities

def view_all_data():
    """Display all data in the database for debugging"""
    conn, cursor = connect_db()
    
    print("\n--- USERS ---")
    cursor.execute("SELECT user_id, username FROM User")
    users = cursor.fetchall()
    for user in users:
        print(f"ID: {user['user_id']}, Username: {user['username']}")
    
    print("\n--- USER ACTIVITIES ---")
    cursor.execute("SELECT * FROM UserActivities")
    activities = cursor.fetchall()
    for act in activities:
        print(f"Activity ID: {act['activity_id']}, User ID: {act['user_id']}")
        print(f"URL: {act['url']}, Type: {act['scan_type']}")
        print(f"Date: {act['scan_date']}")
        print("-" * 40)
    
    conn.close()

    
# Example usage
if __name__ == "__main__":
    # Test the functions
    user_id = add_user("test_user", "secure_password123")
    
    if user_id:
        # Record some test activities
        record_url_scan(user_id, "https://example.com", "website")
        record_url_scan(user_id, "https://test.com/file.pdf", "file")
        
        # Verify login
        verified_id = verify_user("test_user", "secure_password123")
        print(f"Verified user ID: {verified_id}")
        
        # Get activities
        activities = get_user_activities(user_id)
        print(f"User has {len(activities)} recorded activities")
        for activity in activities:
            print(f"- {activity['url']} ({activity['scan_type']}) scanned on {activity['scan_date']}")
