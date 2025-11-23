import bcrypt
import os
user_data_file = "users.txt"
def hash_password(plain_text_password):
    password_bytes = plain_text_password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")
def verify_password(plain_text_password, hashed_password):
    password_bytes = plain_text_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def register_user(username, password):
    if user_exists(username):
        print(f"Error: User {username} already exists")
        return False

    hashed = hash_password(password)

    with open(user_data_file, "a") as f:
        f.write(f"{username},{hashed}\n")
    print(f"User {username} registered")
    return True

def user_exists(username):
    if not os.path.exists(user_data_file):
        return False


    with open(user_data_file, "r") as f:
        for line in f:
            stored_username, _ = line.strip().split(",")
            if stored_username == username:
                return True

    return False
def login_user(username, password):
    if not os.path.exists(user_data_file):
        print("error: no one registered ")
        return False
    with open(user_data_file, "r") as f:
        for line in f:
            stored_username, stored_hash = line.strip().split(",")
            if stored_username == username:
                if verify_password(stored_hash, password):
                    print(f"yayy... welcome {username}")
                    return True
                else:
                    print(f"error: wrong password")
                    return False
    print(f"error no user trouver")
    return False
def validate_username(username):
    if len(username) < 3 or len(username) > 20:
        return (False, "3-20 characters longg")

    if not username.isalnum():
        return (False, "Username must be alphabets only")

    return (True, "")
def validate_password(password):
    if len(password) < 6 or len(password) > 50:
        return (False, "6 to 50 charaters long plz")
    return(True, "")

def display_menu():
 """Displays the main menu options."""
 print("\n" + "="*50)
 print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
 print(" Secure Authentication System")
 print("="*50)
 print("\n[1] Register a new user")
 print("[2] Login")
 print("[3] Exit")
 print("-"*50)
def main():
    print("=== Secure Authentication System ===")

    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter choice (1/2/3): ")

        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            register_user(username, password)

        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            login_user(username, password)

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
 main()





