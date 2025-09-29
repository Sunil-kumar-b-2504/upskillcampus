import os
import json
from datetime import datetime
import secrets
import string
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet, InvalidToken

DATA_FILE = "passwords.json"
KEY_FILE = "vault.key"

def ensure_key_file_exists(key_file_path: str = KEY_FILE) -> bytes:
    if os.path.exists(key_file_path):
        with open(key_file_path, "rb") as key_file:
            key_bytes = key_file.read().strip()
        if len(key_bytes) != 44:
            raise ValueError("Invalid key file format.")
        return key_bytes
    new_key = Fernet.generate_key()
    tmp_path = key_file_path + ".tmp"
    with open(tmp_path, "wb") as tmp_file:
        tmp_file.write(new_key)
    os.replace(tmp_path, key_file_path)
    try:
        os.chmod(key_file_path, 0o600)
    except Exception:
        pass
    return new_key

def load_fernet_cipher(key_file_path: str = KEY_FILE) -> Fernet:
    key_bytes = ensure_key_file_exists(key_file_path)
    return Fernet(key_bytes)

def load_password_vault(data_file_path: str = DATA_FILE) -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(data_file_path):
        return {}
    try:
        with open(data_file_path, "r", encoding="utf-8") as data_file:
            return json.load(data_file)
    except Exception:
        backup_path = data_file_path + ".bak"
        try:
            os.replace(data_file_path, backup_path)
            print(f"Existing {data_file_path} was invalid and moved to {backup_path}. Starting fresh.")
        except Exception:
            print(f"Could not back up invalid {data_file_path}. Starting fresh with empty vault.")
        return {}

def save_password_vault(password_vault: Dict[str, Dict[str, Any]], data_file_path: str = DATA_FILE) -> None:
    with open(data_file_path, "w", encoding="utf-8") as data_file:
        json.dump(password_vault, data_file, indent=2, ensure_ascii=False)

def generate_strong_password(length: int = 16, use_symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>/?"
    return ''.join(secrets.choice(alphabet) for _ in range(max(4, length)))

def looks_like_fernet_token(value: str) -> bool:
    if not isinstance(value, str):
        return False
    return ("-" in value or "_" in value) and len(value) > 20

def encrypt_plaintext_password(fernet_cipher: Fernet, plaintext_password: str) -> str:
    token_bytes = fernet_cipher.encrypt(plaintext_password.encode("utf-8"))
    return token_bytes.decode("utf-8")

def decrypt_password_token(fernet_cipher: Fernet, token_string: str) -> str:
    token_bytes = token_string.encode("utf-8")
    return fernet_cipher.decrypt(token_bytes).decode("utf-8")

def migrate_plaintext_entries_to_encrypted(password_vault: Dict[str, Dict[str, Any]],
                                           fernet_cipher: Fernet) -> bool:
    vault_changed = False
    for service_name, users_map in list(password_vault.items()):
        if not isinstance(users_map, dict):
            continue
        for username, user_entry in list(users_map.items()):
            if isinstance(user_entry, str):
                encrypted_token = encrypt_plaintext_password(fernet_cipher, user_entry)
                users_map[username] = {
                    "password": encrypted_token,
                    "created": datetime.utcnow().isoformat(),
                    "notes": ""
                }
                vault_changed = True
                continue
            if isinstance(user_entry, dict):
                stored_password_value = user_entry.get("password")
                if stored_password_value is None:
                    continue
                if looks_like_fernet_token(stored_password_value):
                    try:
                        _ = decrypt_password_token(fernet_cipher, stored_password_value)
                    except InvalidToken:
                        reencrypted_token = encrypt_plaintext_password(fernet_cipher, stored_password_value)
                        user_entry["password"] = reencrypted_token
                        vault_changed = True
                else:
                    encrypted_token = encrypt_plaintext_password(fernet_cipher, stored_password_value)
                    user_entry["password"] = encrypted_token
                    vault_changed = True
    return vault_changed

def add_password_entry(service_name: str, username: str, plaintext_password: str,
                       notes: str, fernet_cipher: Fernet) -> None:
    password_vault = load_password_vault()
    service_map = password_vault.setdefault(service_name, {})
    encrypted_token = encrypt_plaintext_password(fernet_cipher, plaintext_password)
    service_map[username] = {
        "password": encrypted_token,
        "notes": notes or "",
        "created": datetime.utcnow().isoformat()
    }
    save_password_vault(password_vault)
    print(f"Saved password for {service_name}:{username}")

def retrieve_password(service_name: str, username: str, fernet_cipher: Fernet) -> Optional[str]:
    password_vault = load_password_vault()
    try:
        user_entry = password_vault[service_name][username]
        token_string = user_entry["password"]
        try:
            return decrypt_password_token(fernet_cipher, token_string)
        except InvalidToken:
            print("ERROR: Unable to decrypt — key mismatch or corrupted data.")
            return None
    except Exception:
        return None

def list_all_services() -> list:
    password_vault = load_password_vault()
    return list(password_vault.keys())

def interactive_cli() -> None:
    fernet_cipher = load_fernet_cipher()
    password_vault = load_password_vault()
    did_migrate = migrate_plaintext_entries_to_encrypted(password_vault, fernet_cipher)
    if did_migrate:
        save_password_vault(password_vault)
        print("Migrated plaintext passwords to encrypted tokens.")
    print("Using key file:", KEY_FILE)
    print("Data file:", DATA_FILE)
    while True:
        print("\nPassword Manager (encrypted JSON)")
        print("1. Add password")
        print("2. Get password")
        print("3. List services")
        print("4. Generate password")
        print("5. Export key (backup)")
        print("6. Exit")
        choice = input("Choose option: ").strip()
        if choice == "1":
            service_name = input("Service: ").strip()
            username = input("Username: ").strip()
            provided_password = input("Password (leave blank to generate): ")
            if not provided_password:
                length_str = input("Length (default 16): ").strip()
                length = int(length_str) if length_str.isdigit() else 16
                provided_password = generate_strong_password(length)
                print("Generated:", provided_password)
            notes = input("Notes (optional): ").strip()
            add_password_entry(service_name, username, provided_password, notes, fernet_cipher)
        elif choice == "2":
            service_name = input("Service: ").strip()
            username = input("Username: ").strip()
            decrypted_password = retrieve_password(service_name, username, fernet_cipher)
            print("Password:", decrypted_password if decrypted_password else "Not found or decryption failed")
        elif choice == "3":
            print("Services:", list_all_services())
        elif choice == "4":
            length_str = input("Length (default 16): ").strip()
            length = int(length_str) if length_str.isdigit() else 16
            password_generated = generate_strong_password(length)
            print("Generated password:", password_generated)
        elif choice == "5":
            export_target_path = input("Export key to (e.g. vault.key.bak): ").strip()
            try:
                with open(KEY_FILE, "rb") as src_file, open(export_target_path, "wb") as dst_file:
                    dst_file.write(src_file.read())
                print("Key exported — store it securely.")
            except Exception as exc:
                print("Export failed:", exc)
        elif choice == "6":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    interactive_cli()
