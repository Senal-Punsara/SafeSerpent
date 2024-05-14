import tkinter as tk
from tkinter import ttk
import ttkbootstrap as ttk
from tkinter import filedialog
from ttkbootstrap.constants import *
import time
import threading
from tkinter import PhotoImage, Label
from PIL import ImageTk, Image
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from encrypt import encrypt_file 
import secrets 


# Function to simulate loading
def loading(root):
    time.sleep(1)  # wait for 5 minutes
    root.destroy()  # close the loading page



def select_file(text_box):
    file_path = filedialog.askopenfilename()
    if file_path:
        # Clear any previous text
        text_box.delete('1.0', ttk.END)
        # Display the selected file path
        text_box.insert(ttk.END, file_path)

def generate_key(password_entry):
    # Generate a random 32-byte (256-bit) key
    key = secrets.token_bytes(32)
    # Convert the key to a hexadecimal string
    key_hex = key.hex()
    # Display the key in the password entry text box
    password_entry.delete('1.0', tk.END)
    password_entry.insert(tk.END, key_hex)

def open_main_window():
    main_window = ttk.Window()
    main_window.title("SafeSerpent")
    main_window.iconbitmap('logo/logo.ico')
    main_window.geometry('800x600')

    tab_control = ttk.Notebook(main_window)

    tab1 = ttk.Frame(tab_control)
    tab_control.add(tab1, text='Encryption')
    topic1 = ttk.Label(tab1, text="Encrypt Your File", font=("Arial", 24),style='info.TLabel', )
    topic1.pack(pady=30)

    file_frame = ttk.Frame(tab1)
    file_label = ttk.Label(file_frame, text="Select File: ", font=("Arial", 15))
    file_label.pack(side=tk.LEFT, padx=5, pady=5)
    
    text_box = ttk.Text(file_frame, height=1, width=50)
    text_box.pack(side=tk.LEFT, padx=5, pady=5)
    
    file_button = ttk.Button(file_frame, text="Browse", command=lambda: select_file(text_box))
    file_button.pack(side=tk.LEFT, padx=5, pady=5)
    
    file_frame.pack(pady=5)

    password_frame = ttk.Frame(tab1)
    password_label = ttk.Label(password_frame, text="  Your Key:", font=("Arial", 15))
    password_label.pack(side=tk.LEFT, padx=5, pady=5)
    
    password_entry = ttk.Text(password_frame, height=1, width=50)
    password_entry.pack(side=tk.LEFT, padx=10, pady=5)
    password_button = ttk.Button(password_frame, text="Create Key", command=lambda: generate_key(password_entry))
    password_button.pack(side=tk.LEFT, padx=0, pady=5)
    
    password_frame.pack(pady=5)
    

    def encrypt_process(text_box, password_entry, status_label,discription_label):
        file_path = text_box.get('1.0', tk.END).strip()  # Get the selected file path
        password = password_entry.get('1.0', tk.END).strip()  # Get the password
        if file_path and password:
            status_label.config(text="Encrypting ...",style='info.TLabel')
            discription_label.config(text="")  # Update label to indicate encryption process
            main_window.update_idletasks()  # Update the label immediately
            encrypted_file_path = file_path + ".enc"  # Define the path for encrypted file
            try:
                encrypt_file(file_path, password, encrypted_file_path)  # Call encrypt_file function
                status_label.config(text=f"Successful !", style='info.TLabel', background="", foreground="green")  # Update label upon success
                discription_label.config(text=f"Encrypted file: {encrypted_file_path}")
                print("File encrypted successfully.")
            except Exception as e:
                status_label.config(text="Encryption failed !", background="", foreground="red")  # Update label if encryption fails
                print(f"Encryption failed: {e}")


# Function to open the main application window
    encrypt_button = ttk.Button(tab1, text="Encrypt",  command=lambda: encrypt_process(text_box, password_entry,status_label,discription_label))
    encrypt_button.pack(pady=20)
    status_label = ttk.Label(tab1, text="", font=("Arial", 15), style='info.TLabel')
    status_label.pack(pady=5) 
    discription_label = ttk.Label(tab1, text="", font=("Arial", 10))
    discription_label.pack(pady=5)

#decryption
    tab2 = ttk.Frame(tab_control)
    tab_control.add(tab2, text='Decryption')
    topic2 = ttk.Label(tab2, text="Decrypt Your File", font=("Arial", 24))
    topic2.pack(pady=30)

    tab_control.pack(expand=1, fill='both')

    main_window.mainloop()

# Function to open the loading page
def open_loading_page():
    # loading_page = ttk.Window(themename="superhero")
    loading_page = ttk.Window()
    loading_page.title("SafeSerpent")
    loading_page.iconbitmap('logo/logo.ico')
    loading_page.geometry('800x600')
    loading_page.resizable(False, False)

    img = Image.open('logo/logo3.png')
    img = img.resize((400, 400))
    image = ImageTk.PhotoImage(img)

    image_label = tk.Label(loading_page, image=image)
    image_label.pack(expand=True, pady=10)

    software_name = ttk.Label(loading_page, text="SafeSerpent", font=("Arial", 32))
    software_name.pack(pady=5)

    label = ttk.Label(loading_page, text="Loading ...",style='primary.TLabel', font=("Arial", 15))
    label.pack(pady=5)

    threading.Thread(target=loading, args=(loading_page,)).start()

    loading_page.mainloop()

    open_main_window()

# Start the application
open_loading_page()
