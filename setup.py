### SPass - By JavierSJ (@Javier3123123)
###   _____ _____         _____ _____ 
###  / ____|  __ \ /\    / ____/ ____|
### | (___ | |__) /  \  | (___| (___  
###  \___ \|  ___/ /\ \  \___ \\___ \ 
###  ____) | |  / ____ \ ____) |___) |
### |_____/|_| /_/    \_\_____/_____/ 

########################################

from setuptools import setup
from setuptools.command.install import install
import os
import sqlite3
from pathlib import Path


class InstallCommand(install):
    def create(self):
        appdata_path = Path(os.getenv('APPDATA')) / 'SPass'

        appdata_path.mkdir(parents=True, exist_ok=True)

        db_path = appdata_path / 'passwords.db'

        if not db_path.exists():
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
        else:
            print(f"[WARNING] La base de datos ya existe. Path: {db_path}")

    def run(self):
        self.create()

        install.run(self)

setup(
    name='spass',
    version='1.0',
    py_modules=['spass'],
    install_requires=[
        'pycryptodome',
        'cryptography',
    ],
    entry_points={
        'console_scripts': [
            'spass=spass:main',
        ],
    },
    cmdclass={
        'install': InstallCommand,
    },
)

### SPass - By JavierSJ (@Javier3123123)
###   _____ _____         _____ _____ 
###  / ____|  __ \ /\    / ____/ ____|
### | (___ | |__) /  \  | (___| (___  
###  \___ \|  ___/ /\ \  \___ \\___ \ 
###  ____) | |  / ____ \ ____) |___) |
### |_____/|_| /_/    \_\_____/_____/ 

########################################