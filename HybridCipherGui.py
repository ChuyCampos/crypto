import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from HybridCipher import HybridCipher, FileManager, RSA

class EncryptSignWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypt and Sign")
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(frame, text="File to Encrypt:", font=("Arial", 12)).grid(row=0, column=0, padx=5, pady=5)
        self.file_entry = ttk.Entry(frame, width=50)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(frame, text="Public Key File:", font=("Arial", 12)).grid(row=1, column=0, padx=5, pady=5)
        self.pubkey_entry = ttk.Entry(frame, width=50)
        self.pubkey_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_pubkey).grid(row=1, column=2, padx=5, pady=5)

        ttk.Label(frame, text="Private Key File:", font=("Arial", 12)).grid(row=2, column=0, padx=5, pady=5)
        self.privkey_entry = ttk.Entry(frame, width=50)
        self.privkey_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_privkey).grid(row=2, column=2, padx=5, pady=5)

        ttk.Button(frame, text="Encrypt and Sign", command=self.encrypt_and_sign).grid(row=3, column=0, columnspan=3, pady=10)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.insert(0, filename)

    def browse_pubkey(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.pubkey_entry.insert(0, filename)

    def browse_privkey(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.privkey_entry.insert(0, filename)

    def encrypt_and_sign(self):
        file_name = self.file_entry.get()
        public_key_path = self.pubkey_entry.get()
        private_key_path = self.privkey_entry.get()
        if not file_name or not public_key_path or not private_key_path:
            messagebox.showerror("Error", "All fields must be filled")
            return
        cipher = HybridCipher()
        if(cipher.cbc_flow_encrypt(file_name, public_key_path, private_key_path)):
            messagebox.showinfo("Success", "File encrypted and signed successfully")

class DecryptVerifyWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Decrypt and Verify")
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(frame, text="File to Decrypt:", font=("Arial", 12)).grid(row=0, column=0, padx=5, pady=5)
        self.file_entry = ttk.Entry(frame, width=50)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(frame, text="Private Key File:", font=("Arial", 12)).grid(row=1, column=0, padx=5, pady=5)
        self.privkey_entry = ttk.Entry(frame, width=50)
        self.privkey_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_privkey).grid(row=1, column=2, padx=5, pady=5)

        ttk.Label(frame, text="Public Key File:", font=("Arial", 12)).grid(row=2, column=0, padx=5, pady=5)
        self.pubkey_entry = ttk.Entry(frame, width=50)
        self.pubkey_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Browse", command=self.browse_pubkey).grid(row=2, column=2, padx=5, pady=5)

        ttk.Button(frame, text="Decrypt and Verify", command=self.decrypt_and_verify).grid(row=3, column=0, columnspan=3, pady=10)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.insert(0, filename)

    def browse_privkey(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.privkey_entry.insert(0, filename)

    def browse_pubkey(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.pubkey_entry.insert(0, filename)

    def decrypt_and_verify(self):
        file_name = self.file_entry.get()
        private_key_path = self.privkey_entry.get()
        public_key_path = self.pubkey_entry.get()
        if not file_name or not private_key_path or not public_key_path:
            messagebox.showerror("Error", "All fields must be filled")
            return
        cipher = HybridCipher()
        
        if(cipher.cbc_flow_decrypt(file_name, private_key_path, public_key_path)):
            messagebox.showinfo("Success", "File decrypted and verified successfully")

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid Cipher Tool")
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(frame, text="Choose an action:", font=("Arial", 16)).grid(row=0, column=0, columnspan=2, pady=10)

        ttk.Button(frame, text="Encrypt and Sign", command=self.open_encrypt_sign_window, width=20).grid(row=1, column=0, padx=10, pady=10)
        ttk.Button(frame, text="Decrypt and Verify", command=self.open_decrypt_verify_window, width=20).grid(row=1, column=1, padx=10, pady=10)

    def open_encrypt_sign_window(self):
        EncryptSignWindow(tk.Toplevel(self.root))

    def open_decrypt_verify_window(self):
        DecryptVerifyWindow(tk.Toplevel(self.root))

def main():
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
