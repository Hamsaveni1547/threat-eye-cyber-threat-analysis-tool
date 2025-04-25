import db_operations as db
import os
import re

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def validate_url(url):
    """Simple URL validation"""
    url_pattern = re.compile(
        r'^(http|https)://'  # http:// or https://
        r'([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?'
        r'(/[a-zA-Z0-9._%+-]+)*/?$'  # path
    )
    return bool(url_pattern.match(url))

def determine_scan_type(url):
    """Determine the scan type based on the URL"""
    if url.endswith(('.pdf', '.doc', '.docx', '.txt', '.zip', '.exe')):
        return "file"
    elif '.com' in url or '.org' in url or '.net' in url:
        return "website"
    else:
        return "unknown"

def login_menu():
    """Display login menu and authenticate user"""
    while True:
        clear_screen()
        print("===== CYBERSECURITY PROJECT =====")
        print("1. Login")
        print("2. Register")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            username = input("Username: ")
            password = input("Password: ")
            user_id = db.verify_user(username, password)
            
            if user_id:
                print(f"Login successful! Welcome {username}.")
                input("Press Enter to continue...")
                return user_id, username
            else:
                print("Invalid username or password.")
                input("Press Enter to continue...")
        
        elif choice == '2':
            username = input("Create a username: ")
            password = input("Create a password: ")
            confirm_password = input("Confirm password: ")
            
            if password != confirm_password:
                print("Passwords don't match!")
                input("Press Enter to continue...")
                continue
                
            user_id = db.add_user(username, password)
            if user_id:
                print(f"Registration successful! Welcome {username}.")
                input("Press Enter to continue...")
                return user_id, username
        
        elif choice == '3':
            print("Goodbye!")
            exit(0)
        
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

def main_menu(user_id, username):
    """Display main menu after login"""
    while True:
        clear_screen()
        print(f"===== Welcome {username} =====")
        print("1. Scan a URL")
        print("2. View Scan History")
        print("3. Logout")
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            scan_url(user_id)
        elif choice == '2':
            view_history(user_id)
        elif choice == '3':
            print("Logging out...")
            break
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

def scan_url(user_id):
    """Scan a URL and record the activity"""
    clear_screen()
    print("===== URL SCANNER =====")
    url = input("Enter a URL to scan (include http:// or https://): ")
    
    if not validate_url(url):
        print("Invalid URL format! Please include http:// or https://")
        input("Press Enter to continue...")
        return
    
    # In a real application, you would implement actual scanning functionality here
    print(f"Scanning {url}...")
    scan_type = determine_scan_type(url)
    print(f"Detected as: {scan_type}")
    
    # Record this scan in the database
    activity_id = db.record_url_scan(user_id, url, scan_type)
    
    print(f"Scan completed and recorded (ID: {activity_id})")
    input("Press Enter to continue...")

def view_history(user_id):
    """View scan history for the user"""
    clear_screen()
    print("===== SCAN HISTORY =====")
    
    activities = db.get_user_activities(user_id)
    
    if not activities:
        print("No scan history found.")
    else:
        print(f"Found {len(activities)} activities:")
        for i, activity in enumerate(activities, 1):
            print(f"{i}. URL: {activity['url']}")
            print(f"   Type: {activity['scan_type']}")
            print(f"   Date: {activity['scan_date']}")
            print("-" * 40)
    
    input("Press Enter to continue...")

# In main.py, add this to your menu options
# Or run directly to test:
import db_operations
db_operations.view_all_data()


if __name__ == "__main__":
    try:
        user_id, username = login_menu()
        main_menu(user_id, username)
    except KeyboardInterrupt:
        print("\nProgram terminated.")
    except Exception as e:
        print(f"An error occurred: {e}")