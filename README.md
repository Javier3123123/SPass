
# SPass - Secure Password Manager

SPass is a secure, open-source password manager built with a command-line interface (CLI). It allows you to store, retrieve, modify, and delete passwords securely using AES encryption and a master key derived with PBKDF2-HMAC.

This project is designed for users who prefer a simple, reliable, and secure solution for managing passwords from the terminal.
## Features

- Generate random passwords with customizable options (uppercase letters, numbers, special characters).
- Uses AES encryption standard to secure passwords.
- Passwords are securely stored in a local SQLite database.
- Manage your credentials, add, modify, or delete passwords directly from the terminal.
- Export your passwords to different formats (CSV, JSON, TXT).
- The master key is hashed using PBKDF2-HMAC to ensure it is resistant to dictionary attacks.

## Requirements

- Python 3.6 or higher

Dependencies are listed in the requirements.txt file. You can install them easily using:

```
pip install -r requirements.txt
```

Alternatively, if you'd like to install the package and its dependencies globally, you can use the setup.py:

```
python setup.py install
```
## Installation

1. Clone the repository:

```
git clone https://github.com/Javier3123123/SPass.git
cd SPass
```

2. Install the dependencies:

You can either use the requirements.txt file to install dependencies:

```
pip install -r requirements.txt
```

Or you can use the setup.py to install the package:

```
python setup.py install
```
## Usage/Examples

### Available commands

1. Create the master key:

If you don't have a master key, you can create one using:

```
python spass.py --create-master-key
```

This will prompt you to enter a new master password and the number of iterations for key derivation.

2. Retrieve stored credentials:

To retrieve your stored passwords, first verify your master key:

```
python spass.py --get-credentials
```

You can also export credentials to various formats (csv, json, txt):

```
python spass.py --get-credentials --export csv --file credentials.csv
```

3. Add new credentials:

You can add new credentials interactively:

```
python spass.py --create-credentials
```

4. Modify credentials:

To modify an existing credential by its ID:

```
python spass.py --modify-credentials -mc ID
```

5. Delete credentials:

To delete a credential by its ID:

```
python spass.py --delete-credentials -dc ID
```

6. Reindex credentials (Defined but not used):

Reindex the credentials to ensure that each ID is unique and ordered:

```
python spass.py --reindex-credentials
```
