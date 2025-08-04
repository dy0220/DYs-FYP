import time
import base64
import hashlib
from Crypto.Cipher import AES
import json
import os
import random
import smtplib
from email.mime.text import MIMEText
import boto3
from botocore.exceptions import NoCredentialsError
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD

# --- Config Paths (relative to script location) --- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_CONFIG_PATH = os.path.join(BASE_DIR, "auth_config.json")
AWS_CONFIG_PATH = os.path.join(BASE_DIR, "aws_config.json")
EMAIL_CONFIG_PATH = os.path.join(BASE_DIR, "email_config.json")

# ---------- Utility Functions ---------- #
def pad(text):
    padding = 16 - len(text) % 16
    return text + chr(padding) * padding

def unpad(text):
    padding = ord(text[-1])
    return text[:-padding]

# ---------- Encryption Methods ---------- #
# Caesar Cipher
def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

# Vigenère Cipher
def vigenere_encrypt(text, key):
    key = key.upper()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    key = key.upper()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base - shift + 26) % 26 + shift_base)
            key_index += 1
        else:
            result += char
    return result

# AES Encryption
def aes_encrypt(text, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(text)
    encrypted_bytes = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def aes_decrypt(cipher_text, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted_bytes = cipher.decrypt(base64.b64decode(cipher_text))
        return unpad(decrypted_bytes.decode('utf-8'))
    except:
        return "Decryption failed. Wrong key or corrupted input."

# Base64 Encoding/Decoding
def base64_encrypt(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def base64_decrypt(cipher_text):
    try:
        return base64.b64decode(cipher_text).decode('utf-8')
    except:
        return "Invalid Base64 input."

# XOR Cipher
def xor_encrypt_decrypt(text, key):
    key = key * (len(text) // len(key)) + key[:len(text) % len(key)]
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(text, key))

def xor_encrypt_decrypt_bytes(data: bytes, key: str) -> bytes:
    key_bytes = key.encode('utf-8')
    key_repeated = (key_bytes * (len(data) // len(key_bytes) + 1))[:len(data)]
    return bytes([b ^ k for b, k in zip(data, key_repeated)])

# ---------- AWS S3 Upload ---------- #
def upload_to_s3(file_path, config_path=AWS_CONFIG_PATH):
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)

        s3 = boto3.client(
            's3',
            aws_access_key_id=config['AWSAccessKey'],
            aws_secret_access_key=config['AWSSecretAccessKey'],
            region_name=config['AWSRegion']
        )

        bucket = config['AWSS3BucketName']
        file_name = os.path.basename(file_path)
        s3_key = f"EncryptedFiles/{file_name}"

        s3.upload_file(file_path, bucket, s3_key)

        file_url = f"https://{bucket}.s3.{config['AWSRegion']}.amazonaws.com/{s3_key}"
        return file_url

    except FileNotFoundError:
        return "AWS config file not found."
    except NoCredentialsError:
        return "Invalid AWS credentials."
    except Exception as e:
        return f"Upload error: {str(e)}"
    
# ---------- MFA Email OTP Functions ---------- #
def load_email_config(config_path=EMAIL_CONFIG_PATH):
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load email config: {e}")
        return None

def send_otp(receiver_email, otp, config):
    try:
        msg = MIMEText(f"Your LockBox OTP code is: {otp}")
        msg['Subject'] = "LockBox Verification Code"
        msg['From'] = config['SenderEmail']
        msg['To'] = receiver_email

        server = smtplib.SMTP(config['SMTPServer'], config['SMTPPort'])
        server.starttls()
        server.login(config['SenderEmail'], config['SenderPassword'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False
    
# ---------- OTP Verification Page ---------- #
class OTPWindow:
    def __init__(self, master, on_success):
        self.master = master
        self.master.title("Email Verification")
        self.master.geometry("300x200")
        self.master.configure(bg="#1e1e1e")
        self.otp = None
        self.otp_timestamp = None
        self.on_success = on_success

        tk.Label(master, text="Enter your email:", bg="#1e1e1e", fg="white").pack(pady=(15, 5))
        self.email_entry = tk.Entry(master, width=30)
        self.email_entry.pack()

        tk.Button(master, text="Send OTP", command=self.send_otp_to_email, bg="#4CAF50", fg="white").pack(pady=10)

        self.otp_entry = tk.Entry(master, width=20)
        self.otp_entry.pack(pady=(10, 5))
        self.otp_entry.config(state='disabled')

        self.verify_btn = tk.Button(master, text="Verify OTP", command=self.verify_otp, bg="#2196F3", fg="white")
        self.verify_btn.pack()
        self.verify_btn.config(state='disabled')

    def send_otp_to_email(self):
        config = load_email_config()
        if not config:
            messagebox.showerror("Error", "Failed to load email config.")
            return

        email = self.email_entry.get()
        if not email:
            messagebox.showerror("Error", "Please enter your email.")
            return

        self.otp = str(random.randint(100000, 999999))
        self.otp_timestamp = time.time()
        success = send_otp(email, self.otp, config)
        if success:
            messagebox.showinfo("Success", f"OTP sent to {email}")
            self.otp_entry.config(state='normal')
            self.verify_btn.config(state='normal')
        else:
            messagebox.showerror("Error", "Failed to send OTP.")

    def verify_otp(self):
        if not self.otp or not self.otp_timestamp:
            messagebox.showerror("Error", "OTP not generated.")
            return

        if time.time() - self.otp_timestamp > 300:  # 300 seconds = 5 minutes # OTP expired after 5 minutes
            messagebox.showerror("Expired", "OTP has expired. Please request a new one.")
            return
        
        entered = self.otp_entry.get()
        if entered == self.otp:
            self.master.destroy()
            run_gui_app()
        else:
            messagebox.showerror("Access Denied", "Incorrect OTP or Expired.")

# ---------- Authentication Config (Login Page) ---------- #
def load_expected_password(config_path=AUTH_CONFIG_PATH):
    try:
        with open(config_path, 'r') as f:
            return json.load(f).get("AccessPassword", "")
    except Exception as e:
        print(f"Error loading auth config: {e}")
        return ""

class LoginScreen:
    def __init__(self, master):
        self.master = master
        self.expected_password = load_expected_password()

        master.title("LockBox Login")
        master.geometry("300x180")
        master.configure(bg="#1e1e1e")
        master.resizable(False, False)

        tk.Label(master, text="Enter Access Password", bg="#1e1e1e", fg="white", font=("Segoe UI", 12)).pack(pady=(20, 10))
        self.password_entry = tk.Entry(master, show="*", width=25, font=("Segoe UI", 11))
        self.password_entry.pack(pady=5)
        self.password_entry.bind('<Return>', self.check_password)
        tk.Button(master, text="Login", command=self.check_password, bg="#4CAF50", fg="white", width=15).pack(pady=10)

    def check_password(self, event=None):
        if self.password_entry.get() == self.expected_password:
            self.master.destroy()
            root = tk.Tk()
            OTPWindow(root, on_success=run_gui_app)
            root.mainloop()
        else:
            messagebox.showerror("Access Denied", "Incorrect password.")

# ---------- GUI ---------- #
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LockBox")
        self.file_path = None
        self.file_type = None  # .txt or .docx

        self.drop_label = tk.Label(root, text="Drag and drop a .txt or .docx file here", width=60, height=5, bg="#79ffe9", fg="#000000")
        self.drop_label.pack(pady=10)
        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind("<<Drop>>", self.handle_drop)

        self.mode = tk.StringVar(value="Encrypt")
        ttk.Label(root, text="Operation:").pack()
        ttk.Combobox(root, textvariable=self.mode, values=["Encrypt", "Decrypt"], state="readonly").pack()

        self.method = tk.StringVar(value="Caesar Cipher")
        ttk.Label(root, text="Method:").pack()
        self.method_box = ttk.Combobox(root, textvariable=self.method, values=[
            "Caesar Cipher", "Vigenère Cipher", "AES", "Base64", "XOR Cipher"
        ], state="readonly")
        self.method_box.pack()
        self.method_box.bind("<<ComboboxSelected>>", self.toggle_key_input)

        self.key_label = ttk.Label(root, text="Key/Password/Shift:")
        self.key_label.pack()
        self.key_entry = ttk.Entry(root, width=30)
        self.key_entry.pack()

        ttk.Button(root, text="Start", command=self.process_file).pack(pady=10)

        self.output_text = tk.Text(root, height=12, wrap="word")
        self.output_text.pack(padx=10, pady=5)

    def handle_drop(self, event):
        path = event.data.strip('{}')
        ext = os.path.splitext(path)[-1].lower()
        if ext not in ['.txt', '.docx']:
            messagebox.showerror("Invalid File", "Only .txt and .docx files are supported.")
            return
        self.file_path = path
        self.file_type = ext
        self.drop_label.config(text=f"File selected:\n{self.file_path}")

    def toggle_key_input(self, event=None):
        method = self.method.get()
        if method == "Base64":
            self.key_label.pack_forget()
            self.key_entry.pack_forget()
        else:
            self.key_label.pack()
            self.key_entry.pack()

    def process_file(self):
        if not self.file_path:
            messagebox.showerror("Error", "No file selected.")
            return

        try:
            if self.file_type == '.txt':
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            elif self.file_type == '.docx':
                with open(self.file_path, 'rb') as f:
                    content = f.read().hex()
        except:
            messagebox.showerror("Error", "Failed to read file.")
            return

        method = self.method.get()
        mode = self.mode.get()
        key = self.key_entry.get()
        result = ""

        try:
            if method == "Caesar Cipher":
                shift = int(key) if key.isdigit() else 3
                result = caesar_encrypt(content, shift) if mode == "Encrypt" else caesar_decrypt(content, shift)
            elif method == "Vigenère Cipher":
                if not key:
                    raise ValueError("Key required for Vigenère Cipher.")
                result = vigenere_encrypt(content, key) if mode == "Encrypt" else vigenere_decrypt(content, key)
            elif method == "AES":
                if not key:
                    raise ValueError("Password required for AES.")
                result = aes_encrypt(content, key) if mode == "Encrypt" else aes_decrypt(content, key)
            elif method == "Base64":
                result = base64_encrypt(content) if mode == "Encrypt" else base64_decrypt(content)
            elif method == "XOR Cipher":
                if not key:
                    raise ValueError("Key required for XOR Cipher.")
                if self.file_type == '.txt':
                    result = xor_encrypt_decrypt(content, key)
                else:
                    messagebox.showwarning("XOR Cipher Not Supported", "XOR cipher can only be used with .txt files.")
                    return
        except Exception as e:
            result = f"Error: {str(e)}"

        original_name = os.path.splitext(os.path.basename(self.file_path))[0]
        if original_name.upper().endswith('_ENCRYPTED'):
            original_name = original_name[:-10]

        # DECRYPTION MODE
        if mode == "Decrypt":
            try:
                # Attempt to decode hex and write as binary .docx
                output_bytes = bytes.fromhex(result)
                out_file = f"{original_name}_DECRYPTED.docx"
                with open(out_file, 'wb') as f:
                    f.write(output_bytes)
                messagebox.showinfo("Success", f"Decrypted .docx saved to: {out_file}")
            except Exception as e:
                out_file = f"{original_name}_DECRYPTED.txt"
                with open(out_file, 'w', encoding='utf-8') as f:
                    f.write(result)
                messagebox.showwarning("Fallback", f"Saved as .txt instead due to error: {e}")
        else:
            # ENCRYPTION MODE
            out_file = f"{original_name}_ENCRYPTED.txt"
            with open(out_file, 'w', encoding='utf-8') as f:
                f.write(result if isinstance(result, str) else base64.b64encode(result).decode('utf-8'))
            file_url = upload_to_s3(out_file)
            # Only show the download link in the GUI
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"File uploaded to:\n{file_url}")
            messagebox.showinfo("Success", f"Encrypted file saved to: {out_file}")

# ---------- Entry Point ---------- #
def run_gui_app():
    root = TkinterDnD.Tk()
    EncryptionApp(root)
    root.mainloop()

def run_login():
    root = tk.Tk()
    LoginScreen(root)
    root.mainloop()

if __name__ == "__main__":
    run_login()
