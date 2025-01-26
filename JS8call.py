import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import re

# Marker for encrypted payload
ENCRYPTION_MARKER_START = "===ENCRYPTED==="
ENCRYPTION_MARKER_END = "===END==="

# Derive a 32-byte key from a password
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=100000,  # Adjust for security/performance
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Validate password (only letters and numbers allowed)
def validate_password(password):
    return re.match(r"^[A-Za-z0-9]+$", password) is not None

# Clear both input and output windows
def clear_all():
    text_input.delete("1.0", tk.END)  # Clear input text box
    text_output.delete("1.0", tk.END)  # Clear output text box
    error_label.config(text="", bg="white")  # Reset error label

# Show message in the GUI (error or success)
def show_message(message, is_error=True):
    if is_error:
        error_label.config(text=message, bg="red", fg="white")  # Error message
    else:
        error_label.config(text=message, bg="green", fg="white")  # Success message

# Copy results to clipboard
def copy_results():
    results = text_output.get("1.0", tk.END).strip()
    if results:
        app.clipboard_clear()  # Clear the clipboard
        app.clipboard_append(results)  # Add results to clipboard
        show_message("Results copied to clipboard!", is_error=False)  # Success message
    else:
        show_message("No results to copy.")  # Error message

# Paste text from clipboard
def paste_text():
    try:
        clipboard_text = app.clipboard_get()  # Get text from clipboard
        text_input.delete("1.0", tk.END)  # Clear input box
        text_input.insert(tk.END, clipboard_text)  # Insert clipboard text
    except tk.TclError:
        show_message("Clipboard is empty or contains non-text data.")  # Error message

# Encrypt text
def encrypt_text():
    text = text_input.get("1.0", tk.END).strip()
    if not text:
        show_message("Please enter text to encrypt.")
        return

    password = password_input.get().strip()
    if not password:
        show_message("Please enter a password.")
        return

    # Validate password
    if not validate_password(password):
        show_message("Password can only contain letters and numbers.")
        return

    try:
        # Generate a random salt
        salt = os.urandom(16)
        key = derive_key(password, salt)
        cipher_suite = Fernet(key)
        encrypted_text = cipher_suite.encrypt(text.encode())

        # Convert encrypted text to Base32
        encrypted_output = base64.b32encode(salt + encrypted_text).decode()
        encrypted_output = encrypted_output.replace("=", "")  # Remove padding

        # Add markers to the encrypted output
        encrypted_output_with_markers = f"{ENCRYPTION_MARKER_START}\n{encrypted_output}\n{ENCRYPTION_MARKER_END}"
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, encrypted_output_with_markers)
        show_message("Encryption successful!", is_error=False)  # Success message
    except Exception as e:
        show_message(f"Encryption failed: {str(e)}")  # Error message

# Decrypt text
def decrypt_text():
    text = text_input.get("1.0", tk.END).strip()
    if not text:
        show_message("Please enter text to decrypt.")
        return

    password = password_input.get().strip()
    if not password:
        show_message("Please enter a password.")
        return

    # Validate password
    if not validate_password(password):
        show_message("Password can only contain letters and numbers.")
        return

    try:
        # Extract the encrypted payload between the markers
        if ENCRYPTION_MARKER_START in text and ENCRYPTION_MARKER_END in text:
            encrypted_output = text.split(ENCRYPTION_MARKER_START)[1].split(ENCRYPTION_MARKER_END)[0].strip()
        else:
            encrypted_output = text.strip()

        # Add padding if necessary (Base32 requires padding to be a multiple of 8)
        padding_length = len(encrypted_output) % 8
        if padding_length != 0:
            encrypted_output += "=" * (8 - padding_length)

        # Decode the Base32 payload
        try:
            encrypted_output_bytes = base64.b32decode(encrypted_output.encode())
        except base64.binascii.Error:
            show_message("Invalid input format: Not valid Base32.")
            return

        # Ensure the input is long enough to contain the salt
        if len(encrypted_output_bytes) < 16:
            show_message("Invalid input format: Input too short.")
            return

        # Extract the salt and encrypted text
        salt = encrypted_output_bytes[:16]  # First 16 bytes are the salt
        encrypted_text = encrypted_output_bytes[16:]  # The rest is the encrypted text

        # Derive the key using the password and salt
        key = derive_key(password, salt)
        cipher_suite = Fernet(key)
        decrypted_text = cipher_suite.decrypt(encrypted_text).decode()

        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, decrypted_text)
        show_message("Decryption successful!", is_error=False)  # Success message
    except InvalidToken:
        show_message("Decryption failed: Invalid password or corrupted data.")  # Error message
    except Exception as e:
        show_message(f"Decryption failed: {str(e)}")  # Error message

# Create the GUI
app = tk.Tk()
app.title("AES-256 Encryption Tool")

# Text input
tk.Label(app, text="Enter Text:").pack()
text_input = tk.Text(app, height=5, width=50)
text_input.pack()

# Paste button (near the top)
paste_button = tk.Button(app, text="Paste", command=paste_text)
paste_button.pack(pady=5)

# Password input
tk.Label(app, text="Enter Password (letters and numbers only):").pack()
password_input = tk.Entry(app, width=50, show="*")  # Hide password input
password_input.pack()

# Buttons
button_frame = tk.Frame(app)
button_frame.pack(pady=10)

tk.Button(button_frame, text="Encrypt", command=encrypt_text).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Decrypt", command=decrypt_text).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Clear", command=clear_all).pack(side=tk.LEFT, padx=5)

# Output
tk.Label(app, text="Result:").pack()
text_output = tk.Text(app, height=5, width=50)
text_output.pack()

# Copy Results button (near the bottom)
copy_button = tk.Button(app, text="Copy Results", command=copy_results)
copy_button.pack(pady=5)

# Error/Success label
error_label = tk.Label(app, text="", bg="white", fg="black", width=50, height=2)
error_label.pack(pady=10)

# Run the application
app.mainloop()