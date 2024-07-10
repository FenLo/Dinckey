import sys
import json
import base64
import string
import random
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QListWidget, QLabel, QMessageBox, QInputDialog)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google.auth.transport.requests import Request

# Google Drive API permissions
SCOPES = ['https://www.googleapis.com/auth/drive.file']

class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DincKey")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon('icon.png'))  # Specify the path to the icon file
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2c3e50;
            }
            QLabel {
                color: #ecf0f1;
                font-size: 16px;
            }
            QLineEdit {
                padding: 8px;
                font-size: 14px;
                border: 2px solid #3498db;
                border-radius: 5px;
                background-color: #34495e;
                color: #ecf0f1;
            }
            QPushButton {
                padding: 10px;
                font-size: 14px;
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QListWidget {
                background-color: #34495e;
                color: #ecf0f1;
                border: 2px solid #3498db;
                border-radius: 5px;
                font-size: 14px;
            }
        """)

        self.passwords = {}
        self.key = None
        self.fernet = None
        self.master_password_hash = None
        self.drive_service = None  # Google Drive service object

        self.init_ui()
        self.load_master_password()
        self.authenticate_google_drive()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout()

        # Left side (input fields and buttons)
        left_layout = QVBoxLayout()

        self.service_label = QLabel("Service:")
        self.service_entry = QLineEdit()
        self.email_label = QLabel("E-posta:")
        self.email_entry = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Normal)  # Show password

        self.add_button = QPushButton("add/Change")
        self.add_button.setIcon(QIcon('add_icon.png'))  # Specify the path to the icon file
        self.add_button.clicked.connect(self.add_password)

        self.generate_button = QPushButton("Create password")
        self.generate_button.setIcon(QIcon('generate_icon.png'))  # Specify the path to the icon file
        self.generate_button.clicked.connect(self.generate_password)

        self.delete_button = QPushButton("Delete registery")
        self.delete_button.setIcon(QIcon('delete_icon.png'))  # Specify the path to the icon file
        self.delete_button.clicked.connect(self.delete_account)

        left_layout.addWidget(self.service_label)
        left_layout.addWidget(self.service_entry)
        left_layout.addWidget(self.email_label)
        left_layout.addWidget(self.email_entry)
        left_layout.addWidget(self.password_label)
        left_layout.addWidget(self.password_entry)
        left_layout.addWidget(self.add_button)
        left_layout.addWidget(self.generate_button)
        left_layout.addWidget(self.delete_button)
        left_layout.addStretch()

        # Right side (account list)
        right_layout = QVBoxLayout()

        self.accounts_label = QLabel("Registrations:")
        self.accounts_list = QListWidget()
        self.accounts_list.itemClicked.connect(self.show_password)

        right_layout.addWidget(self.accounts_label)
        right_layout.addWidget(self.accounts_list)

        main_layout.addLayout(left_layout, 1)
        main_layout.addLayout(right_layout, 2)

        central_widget.setLayout(main_layout)

    def load_master_password(self):
        try:
            with open("passwords.json", "r") as f:
                data = json.load(f)
                self.master_password_hash = data.get('master_password_hash')
                self.get_master_password()
        except FileNotFoundError:
            self.create_master_password()

    def create_master_password(self):
        password, ok = QInputDialog.getText(self, "Create master passwrod",
                                            "write the master password:",
                                            QLineEdit.EchoMode.Password)
        if ok and password:
            self.set_encryption_key(password)
            with open("passwords.json", "w") as f:
                json.dump({'master_password_hash': self.master_password_hash}, f)
            self.load_passwords()
            self.update_account_list()
        else:
            sys.exit()

    def get_master_password(self):
        password, ok = QInputDialog.getText(self, "Master password",
                                            "Master password:",
                                            QLineEdit.EchoMode.Password)
        if ok and password:
            if self.verify_master_password(password):
                self.set_encryption_key(password)
                self.load_passwords()
                self.update_account_list()
            else:
                QMessageBox.critical(self, "error", "wrong master password.")
                sys.exit()
        else:
            sys.exit()

    def set_encryption_key(self, master_password):
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.fernet = Fernet(self.key)
        self.master_password_hash = self.encrypt(master_password)

    def verify_master_password(self, password):
        try:
            salt = b'salt_'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            fernet = Fernet(key)
            decrypted = fernet.decrypt(self.master_password_hash.encode()).decode()
            return decrypted == password
        except:
            return False

    def encrypt(self, data):
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, data):
        return self.fernet.decrypt(data.encode()).decode()

    def add_password(self):
        service = self.service_entry.text()
        email = self.email_entry.text()
        password = self.password_entry.text()
        if service and email and password:
            encrypted_email = self.encrypt(email)
            encrypted_password = self.encrypt(password)
            self.passwords[service] = {
                'email': encrypted_email,
                'password': encrypted_password
            }
            self.save_passwords()
            self.update_account_list()
            self.upload_to_google_drive()  # Upload to Google Drive
            QMessageBox.information(self, "Succesfull", "Password added/changed and uploaded to Google Drive.")
            self.service_entry.clear()
            self.email_entry.clear()
            self.password_entry.clear()
        else:
            QMessageBox.warning(self, "Error", "Please enter service, email and password.")

    def show_password(self, item):
        service = item.text()
        if service in self.passwords:
            decrypted_email = self.decrypt(self.passwords[service]['email'])
            decrypted_password = self.decrypt(self.passwords[service]['password'])
            self.service_entry.setText(service)
            self.email_entry.setText(decrypted_email)
            self.password_entry.setText(decrypted_password)
        else:
            QMessageBox.warning(self, "Error", "No password found for this service.")

    def update_account_list(self):
        self.accounts_list.clear()
        for service in self.passwords:
            self.accounts_list.addItem(service)

    def save_passwords(self):
        encrypted_passwords = {}
        for service, data in self.passwords.items():
            encrypted_email = self.encrypt(data['email'])
            encrypted_password = self.encrypt(data['password'])
            encrypted_passwords[service] = {
                'email': encrypted_email,
                'password': encrypted_password
            }
        with open("passwords.json", "w") as f:
            json.dump({'master_password_hash': self.master_password_hash, 'passwords': encrypted_passwords}, f)

    def load_passwords(self):
        try:
            with open("passwords.json", "r") as f:
                data = json.load(f)
                self.master_password_hash = data.get('master_password_hash')
                encrypted_passwords = data.get('passwords', {})
                self.passwords = {}
                for service, data in encrypted_passwords.items():
                    decrypted_email = self.decrypt(data['email'])
                    decrypted_password = self.decrypt(data['password'])
                    self.passwords[service] = {
                        'email': decrypted_email,
                        'password': decrypted_password
                    }
        except FileNotFoundError:
            self.passwords = {}

    def generate_password(self):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(10))
        self.password_entry.setText(password)

    def delete_account(self):
        selected_item = self.accounts_list.currentItem()
        if selected_item:
            service = selected_item.text()
            reply = QMessageBox.question(self, 'Approval', f"{service} Are you sure you want to delete the account?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                del self.passwords[service]
                self.save_passwords()
                self.update_account_list()
                self.service_entry.clear()
                self.email_entry.clear()
                self.password_entry.clear()
        else:
            QMessageBox.warning(self, "Error", "Select account to delete.")

    def authenticate_google_drive(self):
        """Google Drive authenticates to the API."""
        creds = None
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'client_secret.json', SCOPES)
                creds = flow.run_local_server(port=0)
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
        self.drive_service = build('drive', 'v3', credentials=creds)

    def upload_to_google_drive(self):
        """uploads the passwords.json file to Google Drive."""
        folder_id = self.create_or_find_folder('passwords')  # create or find a folder called passwords
        file_metadata = {
            'name': 'passwords.json',
            'mimeType': 'application/json',
            'parents': [folder_id]  # upload passwords.json file to passwords folder
        }
        media = MediaFileUpload('passwords.json',
                                mimetype='application/json')
        file = self.drive_service.files().create(body=file_metadata,
                                                 media_body=media,
                                                 fields='id').execute()
        print('File ID: %s' % file.get('id'))

    def create_or_find_folder(self, folder_name):
        """Creates or finds a specific folder in Google Drive."""
        page_token = None
        query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'"

        while True:
            response = self.drive_service.files().list(q=query,
                                                       spaces='drive',
                                                       fields='nextPageToken, files(id, name)',
                                                       pageToken=page_token).execute()
            for file in response.get('files', []):
                if file.get('name') == folder_name:
                    return file.get('id')
            page_token = response.get('nextPageToken', None)
            if page_token is None:
                break

        # If the folder is not found, create it as new
        folder_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder'
        }
        folder = self.drive_service.files().create(body=folder_metadata,
                                                   fields='id').execute()
        return folder.get('id')


if __name__ == "__main__":
    app = QApplication(sys.argv)
    password_manager = PasswordManager()
    password_manager.show()
    sys.exit(app.exec())
