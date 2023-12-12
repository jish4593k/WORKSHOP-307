import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES


class KeyLoader:
    @staticmethod
    def load_key(path):
        with open(path) as file:
            return file.read().strip()


class EncryptPasswordsLoader:
    @staticmethod
    def load_encrypt_passwords(path):
        encrypt_passwords = []
        with open(path) as file:
            for idx, line in enumerate(file):
                if idx <= 1:
                    continue
                try:
                    line = [el.strip() for el in line.split("|")]
                    ip, usr, pw = line[0], line[1], line[2].strip('*').strip()
                    encrypt_passwords.append((ip, usr, pw))
                except IndexError:
                    break
        return encrypt_passwords


class PasswordDecryptor:
    @staticmethod
    def pkcs7_unpadding(text):
        length = len(text)
        padding_length = ord(text[-1])
        return text[0:length - padding_length]

    @staticmethod
    def decrypt(key, enc_passwords):
        passwords = []
        key_bytes = bytes.fromhex(key)
        for ip, usr, enc_password in enc_passwords:
            content = base64.b64decode(enc_password)
            iv_bytes = content[:16]
            enc_password_bytes = content[16:]
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            password_bytes = cipher.decrypt(enc_password_bytes)
            password = str(password_bytes, encoding='utf-8')
            password = PasswordDecryptor.pkcs7_unpadding(password)
            line = f'{ip}:{usr}:{password}'
            passwords.append(line)
        return passwords


class PasswordDecryptorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Decryptor App")
        self.key_loader = KeyLoader()
        self.encrypt_loader = EncryptPasswordsLoader()
        self.decryptor = PasswordDecryptor()

        # Load Key Button
        self.load_key_button = tk.Button(master, text="Load Key", command=self.load_key)
        self.load_key_button.pack()

        # Load Encrypted Passwords Button
        self.load_encrypt_passwords_button = tk.Button(
            master, text="Load Encrypted Passwords", command=self.load_encrypt_passwords
        )
        self.load_encrypt_passwords_button.pack()

        # Decrypt Passwords Button
        self.decrypt_button = tk.Button(master, text="Decrypt Passwords", command=self.decrypt)
        self.decrypt_button.pack()

        # Save Decrypted Passwords Button
        self.save_decrypted_button = tk.Button(
            master, text="Save Decrypted Passwords", command=self.save_decrypted
        )
        self.save_decrypted_button.pack()

    def load_key(self):
        file_path = filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.dat")])
        if file_path:
            self.key = self.key_loader.load_key(file_path)
            messagebox.showinfo("Info", "Key loaded successfully.")

    def load_encrypt_passwords(self):
        file_path = filedialog.askopenfilename(
            title="Select Encrypted Passwords File", filetypes=[("Text Files", "*.txt")]
        )
        if file_path:
            self.encrypt_passwords = self.encrypt_loader.load_encrypt_passwords(file_path)
            messagebox.showinfo("Info", "Encrypted passwords loaded successfully.")

    def decrypt(self):
        if hasattr(self, "key") and hasattr(self, "encrypt_passwords"):
            self.passwords = self.decryptor.decrypt(self.key, self.encrypt_passwords)
            messagebox.showinfo("Info", "Passwords decrypted successfully.")
        else:
            messagebox.showerror("Error", "Key or encrypted passwords not loaded.")

    def save_decrypted(self):
        file_path = filedialog.asksaveasfilename(
            title="Save Decrypted Passwords", defaultextension=".txt", filetypes=[("Text Files", "*.txt")]
        )
        if file_path:
            data = '\n'.join(self.passwords)
            with open(file_path, 'w') as file:
                file.write(data)
            messagebox.showinfo("Info", "Decrypted passwords saved successfully.")


def main():
    root = tk.Tk()
    app = PasswordDecryptorApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
