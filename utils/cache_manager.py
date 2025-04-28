from datetime import datetime, timedelta
import sqlite3
import json

class CacheManager:
    def __init__(self, db_path='cache.db'):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS cache
                     (key TEXT PRIMARY KEY, value TEXT, timestamp TEXT)''')
        conn.commit()
        conn.close()
    
    def get(self, key, max_age_hours=24):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT value, timestamp FROM cache WHERE key = ?', (key,))
        result = c.fetchone()
        conn.close()
        
        if result:
            value, timestamp = result
            cached_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            if datetime.now() - cached_time < timedelta(hours=max_age_hours):
                return json.loads(value)
        return None
    
    def set(self, key, value):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO cache VALUES (?, ?, ?)',
                 (key, json.dumps(value), datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()

cache_manager = CacheManager()
