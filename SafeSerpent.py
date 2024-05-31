import hashlib
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as ttk
from PIL import ImageTk, Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tkinter import PhotoImage
import os
import base64
import time

class SafeSerpentApp(tk.Tk):
    
    def __init__(self):
        super().__init__()
        self.title("SafeSerpent")
        self.geometry("560x320")
        logo = PhotoImage(file='./_internal/logo.png')
        #self.iconbitmap('./_internal/logo.ico')
        self.iconphoto(False, logo)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.loading_screen()

    def loading_screen(self):
        self.loading_frame = ttk.Frame(self)
        self.loading_frame.pack(expand=True, fill=tk.BOTH)

        label = ttk.Label(self.loading_frame, text="SafeSerpent", font=("Helvetica", 28))
        label.pack(pady=2)

        original_image = Image.open('./_internal/logo.png')  
        resized_image = original_image.resize((200, 200))
        self.image = ImageTk.PhotoImage(resized_image)
        image_label = ttk.Label(self.loading_frame, image=self.image)
        image_label.pack(pady=5)

        label = ttk.Label(self.loading_frame, text="Loading ...", font=("Helvetica", 12))
        label.pack(pady=2)
        progress = ttk.Progressbar(self.loading_frame, mode="determinate", style='Striped.Horizontal.TProgressbar')
        progress.pack(pady=0)
        progress.start()

        self.after(5000, self.main_screen)  

    def main_screen(self):
        self.loading_frame.destroy()
        
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill=tk.BOTH)

        self.encryption_tab = ttk.Frame(self.notebook)
        self.decryption_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.encryption_tab, text="Encryption")
        self.notebook.add(self.decryption_tab, text="Decryption")

        self.create_encryption_tab()
        self.create_decryption_tab()

    def create_encryption_tab(self):
        container = ttk.Frame(self.encryption_tab)
        container.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        ttk.Label(container, text="Encrypt Your File", font=("Helvetica", 20)).grid(row=0, column=1, padx=10, pady=10)
        ttk.Label(container, text="Your File : ", font=("Helvetica", 12)).grid(row=1, column=0, padx=10, pady=10)
        self.enc_file_path = ttk.Entry(container, width=40)
        self.enc_file_path.grid(row=1, column=1, padx=10, pady=10)
        ttk.Button(container, text="Browse", command=self.browse_enc_file, width=7).grid(row=1, column=2, padx=10, pady=10)

        ttk.Label(container, text="Your Key :", font=("Helvetica", 12)).grid(row=2, column=0, padx=10, pady=10)
        self.enc_key = ttk.Entry(container, width=40, show="*")
        self.enc_key.grid(row=2, column=1, padx=10, pady=10)
        self.enc_key_visible = False
        self.toggle_enc_key_button = ttk.Button(container, text="Show", command=self.toggle_enc_key_visibility, width=7)
        self.toggle_enc_key_button.grid(row=2, column=2, padx=10, pady=10)

        self.statusLabelEnc = ttk.Label(container, text="", font=("Helvetica", 15), style='info.TLabel')
        self.statusLabelEnc.grid(row=4, column=1, padx=10, pady=10)
        
        ttk.Button(container, text="Encrypt", command=self.encrypt_file).grid(row=3, column=1, padx=10, pady=10)

    def create_decryption_tab(self):
        container = ttk.Frame(self.decryption_tab)
        container.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        ttk.Label(container, text="Decrypt Your File", font=("Helvetica", 20)).grid(row=0, column=1, padx=10, pady=10)
        ttk.Label(container, text="Your File : ", font=("Helvetica", 12)).grid(row=1, column=0, padx=10, pady=10)
        self.dec_file_path = ttk.Entry(container, width=40)
        self.dec_file_path.grid(row=1, column=1, padx=10, pady=10)
        ttk.Button(container, text="Browse", command=self.browse_dec_file, width=7).grid(row=1, column=2, padx=10, pady=10)

        ttk.Label(container, text="Your Key :", font=("Helvetica", 12)).grid(row=2, column=0, padx=10, pady=10)
        self.dec_key = ttk.Entry(container, width=40, show="*")
        self.dec_key.grid(row=2, column=1, padx=10, pady=10)
        self.dec_key_visible = False
        self.toggle_dec_key_button = ttk.Button(container, text="Show", command=self.toggle_dec_key_visibility, width=7)
        self.toggle_dec_key_button.grid(row=2, column=2, padx=10, pady=10)

        self.statusLabelDec = ttk.Label(container, text="", font=("Helvetica", 15), style='info.TLabel')
        self.statusLabelDec.grid(row=4, column=1, padx=10, pady=10)
        
        ttk.Button(container, text="Decrypt", command=self.decrypt_file).grid(row=3, column=1, padx=10, pady=10)

    def browse_enc_file(self):
        file_path = filedialog.askopenfilename()
        self.enc_file_path.delete(0, tk.END)
        self.enc_file_path.insert(0, file_path)

    def browse_dec_file(self):
        file_path = filedialog.askopenfilename()
        self.dec_file_path.delete(0, tk.END)
        self.dec_file_path.insert(0, file_path)

    def toggle_enc_key_visibility(self):
        if self.enc_key_visible:
            self.enc_key.config(show="*")
            self.toggle_enc_key_button.config(text="Show")
        else:
            self.enc_key.config(show="")
            self.toggle_enc_key_button.config(text="Hide")
        self.enc_key_visible = not self.enc_key_visible

    def toggle_dec_key_visibility(self):
        if self.dec_key_visible:
            self.dec_key.config(show="*")
            self.toggle_dec_key_button.config(text="Show")
        else:
            self.dec_key.config(show="")
            self.toggle_dec_key_button.config(text="Hide")
        self.dec_key_visible = not self.dec_key_visible

    def get_hashed_key(self, user_input):
        # Use SHA-256 to hash the input
        hashed_key = hashlib.sha256(user_input.encode()).digest()
        return hashed_key

    def encrypt_file(self):
        
        self.update_status_enc("Encrypting ...", 2)
        
        file_path = self.enc_file_path.get()
        key = hashlib.sha256(self.enc_key.get().encode()).digest()

        if not file_path or not key:
            messagebox.showerror("Error", "All fields are required.")
            self.update_status_enc("", 2)
            return

        # Start the encryption in a separate thread
        threading.Thread(target=self.encrypt_file_thread, args=(file_path, key)).start()

    def encrypt_file_thread(self, file_path, key):
        try:
            encrypted_path = self.perform_encryption(file_path, key)
            self.update_status_enc("File Encrypted Successfully!", 0) 
            messagebox.showinfo("Success", f"File Encrypted Successfully!\nEncrypted File: {encrypted_path}")
        except Exception as e:
            self.update_status_enc("Encryption Failed", 1) 
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        finally:
            self.update_status_enc("", 2)  

    def decrypt_file(self):
       
        self.update_status_dec("Decrypting ...", 2)
        
        file_path = self.dec_file_path.get()
        key = hashlib.sha256(self.dec_key.get().encode()).digest()

        if not file_path or not key:
            messagebox.showerror("Error", "All fields are required.")
            self.update_status_dec("", 2)
            return

        # Start the decryption in a separate thread
        threading.Thread(target=self.decrypt_file_thread, args=(file_path, key)).start()

    def decrypt_file_thread(self, file_path, key):
        try:
            decrypted_path = self.perform_decryption(file_path, key)
            self.update_status_dec("File Decrypted Successfully!", 0)
            messagebox.showinfo("Success", f"File Decrypted Successfully!\nDecrypted File: {decrypted_path}")
        except Exception as e:
            self.update_status_dec("Decryption Failed", 1)
            messagebox.showerror("Error", f"Decryption Failed: Please Check Your Selected File or the Key.")
        finally:
            self.update_status_dec("", 2)  

    def update_status_enc(self, message, tag):
        if tag == 0:
            self.statusLabelEnc.config(text=message, style='success.TLabel')
        elif tag == 1:
            self.statusLabelEnc.config(text=message, style='danger.TLabel')
        else:
            self.statusLabelEnc.config(text=message, style='info.TLabel')
        self.statusLabelEnc.update_idletasks()
    
    def update_status_dec(self, message, tag):
        if tag == 0:
            self.statusLabelDec.config(text=message, style='success.TLabel')
        elif tag == 1:
            self.statusLabelDec.config(text=message, style='danger.TLabel')
        else:
            self.statusLabelDec.config(text=message, style='info.TLabel')
        self.statusLabelDec.update_idletasks()


    # Function to encrypt a file in chunks
    def perform_encryption(self, input_file, key):
        chunk_size = 64 * 1024  # 64KB chunks
        encrypted_file_path = input_file + ".enc"
        nonce = os.urandom(12)
    
        aesgcm = AESGCM(key)
    
        with open(input_file, 'rb') as f_in, open(encrypted_file_path, 'wb') as f_out:
            f_out.write(nonce)
    
            while True:
                chunk = f_in.read(chunk_size)
                if len(chunk) == 0:
                    break
                ciphertext = aesgcm.encrypt(nonce, chunk, None)
                f_out.write(ciphertext)
        return encrypted_file_path
    
    def add_decrypted_to_filename(self, file_path):
        # Split the file path into directory and base name
        directory, base_name = os.path.split(file_path)
        # Split the base name into file name and extension
        file_name, file_extension = os.path.splitext(base_name)
        # Create the new file name with "(decrypted)" added
        new_file_name = f"{file_name}(decrypted){file_extension}"
        # Combine the directory and the new file name to get the final path
        new_file_path = os.path.join(directory, new_file_name)
        return new_file_path


    # Function to decrypt a file in chunks
    def perform_decryption(self, input_file, key):
        chunk_size = 64 * 1024  # 64KB chunks
        decrypted_file_path = self.add_decrypted_to_filename(input_file[:-4])
        
        with open(input_file, 'rb') as f_in, open(decrypted_file_path, 'wb') as f_out:
            nonce = f_in.read(12)
            aesgcm = AESGCM(key)
    
            while True:
                chunk = f_in.read(chunk_size + 16)
                if len(chunk) == 0:
                    break
                plaintext = aesgcm.decrypt(nonce, chunk, None)
                f_out.write(plaintext)
        return decrypted_file_path
    
    
    def on_closing(self):
        self.destroy()

if __name__ == "__main__":
    app = SafeSerpentApp()
    app.mainloop()
