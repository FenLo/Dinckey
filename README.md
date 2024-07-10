# Dinckey
a Password Manager application with google drive api

# DincKey Password Manager

DincKey is a secure and user-friendly password manager that allows you to store, manage, and encrypt your passwords. It also integrates with Google Drive to back up your passwords securely.

## Features

-   Add, change, and delete password entries.
-   Generate strong random passwords.
-   Encrypt passwords using a master password.
-   Backup encrypted passwords to Google Drive.
-   Securely load and save passwords from a local JSON file.

## Prerequisites

-   Python 3.6 or later
-   Required Python packages (listed in `requirements.txt`)

## Installation

1.  Clone the repository:
    
    bash
    
    Kodu kopyala
    
    `git clone https://github.com/your-username/dinckey.git
    cd dinckey` 
    
2.  Install the required packages:
    
    bash
    
    Kodu kopyala
    
    `pip install -r requirements.txt` 
    

## Setup

### Google Drive API Configuration

1.  Go to the Google Cloud Console.
2.  Create a new project.
3.  Enable the Google Drive API for your project.
4.  Create OAuth 2.0 credentials:
    -   Go to the Credentials page.
    -   Click "Create Credentials" and select "OAuth 2.0 Client IDs".
    -   Set the application type to "Desktop App".
    -   Download the `client_secret.json` file and save it in the project directory.

### Running the Application

1.  Ensure that `client_secret.json` is in the project directory.
2.  Run the application:
    
    bash
    
    Kodu kopyala
    
    `python dinckey.py` 
    
3.  On the first run, you will be prompted to enter and confirm a master password. This master password will be used to encrypt and decrypt your stored passwords.

## Usage

### Adding a Password

1.  Enter the service name in the "Service" field.
2.  Enter the email associated with the service in the "E-posta" field.
3.  Enter the password in the "Password" field.
4.  Click the "Add/Change" button.

### Generating a Password

1.  Click the "Create password" button to generate a random strong password.
2.  The generated password will appear in the "Password" field.

### Deleting a Password

1.  Select an entry from the "Registrations" list.
2.  Click the "Delete registery" button.
3.  Confirm the deletion when prompted.

### Master Password

-   The master password is used to encrypt and decrypt all other passwords.
-   The master password hash is stored in `passwords.json`.
-   If you forget your master password, you will need to delete `passwords.json` and set up the application again.

### Backing Up to Google Drive

-   The application automatically uploads `passwords.json` to Google Drive after each change.
-   Ensure that `token.json` and `client_secret.json` are in the project directory.

## Files

-   `client_secret.json`: Contains your Google API credentials.
-   `token.json`: Stores the user's access and refresh tokens.
-   `passwords.json`: Stores the encrypted passwords and the master password hash.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
