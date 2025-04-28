import sqlite3
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def check_tool_limit(user_id, tool_name, input_data=""):
    DAILY_LIMIT = 4  
    
    try:
        conn = sqlite3.connect("threateye_db.db")
        cur = conn.cursor()
        
        today = datetime.now().date()
        logger.debug(f"Checking limit for user {user_id}, tool {tool_name}, date {today}")
        
        # Check if entry exists for today
        cur.execute("""
            SELECT usage_count FROM tool_usage 
            WHERE user_id = ? AND tool_name = ? AND DATE(usage_date) = DATE(?)
        """, (user_id, tool_name, today))
        
        result = cur.fetchone()
        
        if result:
            current_count = result[0]
            logger.debug(f"Current usage count: {current_count}")
            
            if current_count >= DAILY_LIMIT:
                conn.close()
                return False, "Daily limit reached for this tool"
            
            # Update count
            cur.execute("""
                UPDATE tool_usage 
                SET usage_count = usage_count + 1,
                    input_data = ?
                WHERE user_id = ? AND tool_name = ? AND DATE(usage_date) = DATE(?)
            """, (input_data, user_id, tool_name, today))
        else:
            logger.debug("Creating new entry for today")
            # Create new entry
            cur.execute("""
                INSERT INTO tool_usage (user_id, tool_name, input_data, usage_date, usage_count)
                VALUES (?, ?, ?, ?, 1)
            """, (user_id, tool_name, input_data, today))
        
        conn.commit()
        conn.close()
        return True, "Success"
        
    except Exception as e:
        logger.error(f"Error in check_tool_limit: {str(e)}")
        return False, f"Error: {str(e)}"

def get_tool_usage(user_id):
    try:
        conn = sqlite3.connect("threateye_db.db")
        cur = conn.cursor()
        
        cur.execute("""
            SELECT tool_name, usage_count, usage_date 
            FROM tool_usage 
            WHERE user_id = ? AND DATE(usage_date) = DATE('now')
        """, (user_id,))
        
        usage_data = cur.fetchall()
        conn.close()
        return usage_data
        
    except Exception as e:
        logger.error(f"Error in get_tool_usage: {str(e)}")
        return []
