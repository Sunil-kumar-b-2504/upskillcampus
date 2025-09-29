import random
import string

passwords = {}  # store in memory only

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(chars) for _ in range(length))

def add_password(service, username, password=None):
    if not password:
        password = generate_password()
    if service not in passwords:
        passwords[service] = {}
    passwords[service][username] = password
    print(f"Saved password for {service}:{username}")

def get_password(service, username):
    try:
        return passwords[service][username]
    except KeyError:
        return None

def list_services():
    return list(passwords.keys())

if __name__ == "__main__":
    while True:
        print("\nPassword Manager")
        print("1. Add password")
        print("2. Get password")
        print("3. List services")
        print("4. Exit")
        choice = input("Choose option: ")

        if choice == "1":
            s = input("Service: ")
            u = input("Username: ")
            p = input("Password (leave blank to generate): ")
            add_password(s, u, p if p else None)
        elif choice == "2":
            s = input("Service: ")
            u = input("Username: ")
            pw = get_password(s, u)
            print("Password:", pw if pw else "Not found")
        elif choice == "3":
            print("Services:", list_services())
        elif choice == "4":
            break
        else:
            print("Invalid choice")
