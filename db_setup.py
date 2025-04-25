import sqlite3

def create_database():
    # Connect to SQLite database (creates it if it doesn't exist)
    conn = sqlite3.connect('cybersecurity.db')
    cursor = conn.cursor()
    
    # Create User table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS User (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    ''')
    
    # Create UserActivities table with foreign key relationship to User
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS UserActivities (
        activity_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES User(user_id)
    )
    ''')
    
    # Commit the changes and close the connection
    conn.commit()
    conn.close()
    
    print("Database and tables created successfully!")

if __name__ == "__main__":
    create_database()