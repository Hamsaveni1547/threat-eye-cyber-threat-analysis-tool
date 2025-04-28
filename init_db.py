# init_db.py
import sqlite3

conn = sqlite3.connect("threateye_db.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS tool_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    tool_name TEXT NOT NULL,
    input_data TEXT NOT NULL,
    result_summary TEXT,
    usage_date DATETIME NOT NULL,
    usage_count INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

# print data in the table
# for row in cur.fetchall():
#     print(row)
    
conn.commit()
conn.close()
print("Database initialized.")
