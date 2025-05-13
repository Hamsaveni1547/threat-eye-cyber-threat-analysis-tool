CREATE TABLE IF NOT EXISTS tool_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    tool_name TEXT NOT NULL,
    input_data TEXT NOT NULL,
    result_summary TEXT,
    usage_date DATETIME NOT NULL,
    usage_count INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

# Delete all records from tool_usage first (due to foreign key constraints)
cur.execute("DELETE FROM tool_usage")
print(f"Deleted {cur.rowcount} tool usage records")

# Delete all records from users table
cur.execute("DELETE FROM users")
print(f"Deleted {cur.rowcount} user records")

# Reset the SQLite sequence counter
cur.execute("DELETE FROM sqlite_sequence WHERE name IN ('users', 'tool_usage')")
print("Reset sequence counters for users and tool_usage tables")


DROP TABLE IF EXISTS contact_submissions;
CREATE TABLE contact_submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    company TEXT,
    subject TEXT,
    message TEXT NOT NULL,
    secure_contact BOOLEAN,
    submission_date TIMESTAMP NOT NULL
);