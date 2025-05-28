### SPass - By JavierSJ (@Javier3123123)
###   _____ _____         _____ _____ 
###  / ____|  __ \ /\    / ____/ ____|
### | (___ | |__) /  \  | (___| (___  
###  \___ \|  ___/ /\ \  \___ \\___ \ 
###  ____) | |  / ____ \ ____) |___) |
### |_____/|_| /_/    \_\_____/_____/ 

########################################

import argparse
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import json
import csv
import random
import string
import getpass

appdata_path = Path(os.getenv('APPDATA')) / 'SPass'

db_path = appdata_path / 'passwords.db'

def generate_secure_password(length=16, use_uppercase=True, use_numbers=True, use_special_chars=True):
    characters = string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_special_chars:
        characters += string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def generate_aes_key(master_password: str, salt: bytes, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    key = kdf.derive(master_password.encode())
    return key

def encrypt_text(aes_key, text: str):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    return cipher.iv + ct_bytes

def decrypt_text(aes_key, encrypted_text: bytes):
    iv = encrypted_text[:16]
    ct = encrypted_text[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode()

def create_database():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY,
        service_name BLOB NOT NULL,
        username BLOB NOT NULL,
        password BLOB NOT NULL,
        salt BLOB NOT NULL
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS master_password (
        id INTEGER PRIMARY KEY,
        password BLOB NOT NULL,
        salt BLOB NOT NULL,
        iterations INTEGER NOT NULL
    )''')
    conn.commit()
    conn.close()

def save_master_password(db_conn, master_password: str, iterations: int):
    salt = os.urandom(16)
    hashed_pw = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    ).derive(master_password.encode())
    cursor = db_conn.cursor()
    cursor.execute("INSERT INTO master_password (password, salt, iterations) VALUES (?, ?, ?)", (hashed_pw, salt, iterations))
    db_conn.commit()

def add_password(db_conn, service_name: str, username: str, password: str, master_password: str):
    cursor = db_conn.cursor()
    cursor.execute("SELECT salt FROM master_password ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()
    if not result:
        print("Error: La clave maestra no existe.")
        return

    salt = result[0]
    cursor.execute("SELECT iterations FROM master_password ORDER BY id DESC LIMIT 1")
    iterations = cursor.fetchone()[0]
    aes_key = generate_aes_key(master_password, salt, iterations)
    encrypted_service_name = encrypt_text(aes_key, service_name)
    encrypted_username = encrypt_text(aes_key, username)
    encrypted_password = encrypt_text(aes_key, password)
    cursor.execute("INSERT INTO passwords (service_name, username, password, salt) VALUES (?, ?, ?, ?)",
                   (encrypted_service_name, encrypted_username, encrypted_password, salt))
    db_conn.commit()
    print(f"Credential for {service_name} added successfully.")

def reindex_credentials(db_conn):
    cursor = db_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=OFF;")
    cursor.execute("CREATE TABLE passwords_temp AS SELECT * FROM passwords ORDER BY id;")
    cursor.execute("DROP TABLE passwords;")
    cursor.execute("ALTER TABLE passwords_temp RENAME TO passwords;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    db_conn.commit()
    print("Credential IDs reindexed successfully.")

def verify_master_password(db_conn, input_password: str):
    cursor = db_conn.cursor()
    cursor.execute("SELECT password, salt, iterations FROM master_password ORDER BY id DESC LIMIT 1")
    stored_hashed_pw, salt, iterations = cursor.fetchone()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    try:
        kdf.verify(input_password.encode(), stored_hashed_pw)
        return True
    except Exception:
        return False

def get_credentials(db_conn, master_password: str, export_format=None, filename=None):
    cursor = db_conn.cursor()
    cursor.execute("SELECT id, service_name, username, password, salt FROM passwords")
    passwords = cursor.fetchall()

    if export_format:
        export_data = []
        for password in passwords:
            id, encrypted_service_name, encrypted_username, encrypted_password, salt = password
            aes_key = generate_aes_key(master_password, salt, 100000)
            decrypted_service_name = decrypt_text(aes_key, encrypted_service_name)
            decrypted_username = decrypt_text(aes_key, encrypted_username)
            decrypted_password = decrypt_text(aes_key, encrypted_password)
            export_data.append({
                "id": id,
                "service": decrypted_service_name,
                "username": decrypted_username,
                "password": decrypted_password
            })

        if export_format == "csv":
            with open(filename, "w", newline='') as csvfile:
                fieldnames = ['id', 'service', 'username', 'password']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(export_data)
        elif export_format == "json":
            with open(filename, "w") as jsonfile:
                json.dump(export_data, jsonfile, indent=4)
        elif export_format == "txt":
            with open(filename, "w") as txtfile:
                for entry in export_data:
                    txtfile.write(f"ID: {entry['id']}\nService: {entry['service']}\nUsername: {entry['username']}\nPassword: {entry['password']}\n\n")
        print(f"Credentials exported to {filename}.")
    else:
        for password in passwords:
            id, encrypted_service_name, encrypted_username, encrypted_password, salt = password
            aes_key = generate_aes_key(master_password, salt, 100000)
            decrypted_service_name = decrypt_text(aes_key, encrypted_service_name)
            decrypted_username = decrypt_text(aes_key, encrypted_username)
            decrypted_password = decrypt_text(aes_key, encrypted_password)
            print(f"ID: {id}\nService: {decrypted_service_name}\nUsername: {decrypted_username}\nPassword: {decrypted_password}\n")

def delete_credential(db_conn, credential_id: int):
    cursor = db_conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE id = ?", (credential_id,))
    db_conn.commit()
    cursor.execute("VACUUM")
    db_conn.commit()
    print(f"Credential with ID {credential_id} deleted successfully.")

def modify_credential(db_conn, credential_id: int, service_name: str, username: str, password: str, master_password: str):
    cursor = db_conn.cursor()
    cursor.execute("SELECT salt FROM passwords WHERE id = ?", (credential_id,))
    result = cursor.fetchone()
    if not result:
        print(f"Error: No credential found with ID {credential_id}.")
        return
    salt = result[0]
    cursor.execute("SELECT iterations FROM master_password ORDER BY id DESC LIMIT 1")
    iterations = cursor.fetchone()[0]
    aes_key = generate_aes_key(master_password, salt, iterations)
    encrypted_service_name = encrypt_text(aes_key, service_name)
    encrypted_username = encrypt_text(aes_key, username)
    encrypted_password = encrypt_text(aes_key, password)
    cursor.execute("UPDATE passwords SET service_name = ?, username = ?, password = ? WHERE id = ?",
                   (encrypted_service_name, encrypted_username, encrypted_password, credential_id))
    db_conn.commit()
    print(f"Credential with ID {credential_id} updated successfully.")

def main():
    parser = argparse.ArgumentParser(description="Secure Password Manager")
    parser.add_argument('--create-master-key', '-cmk', action='store_true', help="Create the master password if it doesn't exist.")
    parser.add_argument('--get-credentials', '-gc', action='store_true', help="Get the stored credentials.")
    parser.add_argument('--create-credentials', '-cc', action='store_true', help="Create new credentials interactively.")
    parser.add_argument('--delete-credentials', '-dc', type=int, help="Delete a credential by ID.")
    parser.add_argument('--modify-credentials', '-mc', type=int, help="Modify a credential by ID.")
    parser.add_argument('--export', choices=['csv', 'json', 'txt'], help="Export credentials to a file.")
    parser.add_argument('--file', metavar="FILENAME", help="Filename for exporting credentials.")
    
    args = parser.parse_args()

    conn = sqlite3.connect(db_path)
    create_database()

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM master_password")
    master_password_exists = cursor.fetchone()[0] > 0

    if args.create_master_key:
        if master_password_exists:
            print("Error: La clave maestra ya existe.")
        else:
            master_password = getpass.getpass("Enter your new master password: ")
            iterations = int(input("Enter the number of iterations for key derivation (e.g., 100000): "))
            save_master_password(conn, master_password, iterations)
            print("Master password saved successfully.")
    
    elif args.get_credentials:
        if not master_password_exists:
            print("Error: No se ha creado una clave maestra. No se pueden obtener credenciales.")
            return
        master_password = getpass.getpass("Enter your master password: ")
        if verify_master_password(conn, master_password):
            if args.export:
                if args.file:
                    get_credentials(conn, master_password, args.export, args.file)
                else:
                    print("You must specify a filename to export.")
            else:
                get_credentials(conn, master_password)
        else:
            print("Incorrect master password.")
    
    elif args.create_credentials:
        if not master_password_exists:
            print("Error: No se ha creado una clave maestra. No se pueden agregar credenciales.")
            return

        master_password = getpass.getpass("Enter your master password: ")
        if verify_master_password(conn, master_password):
            while True:
                print("\nAdd a new credential:")
                service_name = input("Enter service name: ")
                username = input("Enter username: ")
                password = getpass.getpass("Enter password: ")

                add_password(conn, service_name, username, password, master_password)
                print("Credential added successfully.")

                more = input("Do you want to add another credential? (y/n): ")
                if more.lower() != 'y':
                    break
        else:
            print("Incorrect master password.")
    
    elif args.delete_credentials:
        if not master_password_exists:
            print("Error: No se ha creado una clave maestra. No se pueden eliminar credenciales.")
            return

        master_password = getpass.getpass("Enter your master password: ")
        if verify_master_password(conn, master_password):
            delete_credential(conn, args.delete_credentials)
        else:
            print("Incorrect master password.")
    
    elif args.modify_credentials:
        if not master_password_exists:
            print("Error: No se ha creado una clave maestra. No se pueden modificar credenciales.")
            return

        master_password = getpass.getpass("Enter your master password: ")
        if verify_master_password(conn, master_password):
            service_name = input("Enter new service name: ")
            username = input("Enter new username: ")
            password = getpass.getpass("Enter new password: ")
            modify_credential(conn, args.modify_credentials, service_name, username, password, master_password)
        else:
            print("Incorrect master password.")
    
    conn.close()

if __name__ == "__main__":
    main()

### SPass - By JavierSJ (@Javier3123123)
###   _____ _____         _____ _____ 
###  / ____|  __ \ /\    / ____/ ____|
### | (___ | |__) /  \  | (___| (___  
###  \___ \|  ___/ /\ \  \___ \\___ \ 
###  ____) | |  / ____ \ ____) |___) |
### |_____/|_| /_/    \_\_____/_____/ 

########################################