import random
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
from encrypt_decrypt import encrypt_file 
from encrypt_decrypt import decrypt_file
import base64
import secrets 

ALGORITHM = "AES"
KEY_SIZE = 32  # 256 bits
ITERATION_COUNT = 100000
TAG_LENGTH = 16  # 128 bits


# Function to simulate loading
def loading(root):
    time.sleep(1)  
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

def encrypt_process(main_window,text_box, password_entry, status_label,discription_label):
    
    file_path = text_box.get('1.0', tk.END).strip()  # Get the selected file path
    password = password_entry.get('1.0', tk.END).strip()  # Get the password
    if file_path and password:
        status_label.config(text="Encrypting ...",style='info.TLabel', background="", foreground="black")
        discription_label.config(text="")  # Update label to indicate encryption process
        main_window.update_idletasks()  # Update the label immediately
        encrypted_file_path = file_path + ".enc"  # Define the path for encrypted file
        try:
            status_label.config(text="")
            status_label.config(text="Encrypting ...",style='info.TLabel', background="", foreground="black")
            encrypt_file(file_path, password, encrypted_file_path)  # Call encrypt_file function
            status_label.config(text=f"Successful !", style='info.TLabel', background="", foreground="green")  # Update label upon success
            discription_label.config(text=f"Encrypted file: {encrypted_file_path}")
            print("File encrypted successfully.")
        except Exception as e:
            status_label.config(text="Encryption failed !", background="", foreground="red")  # Update label if encryption fails
            print(f"Encryption failed: {e}")
            discription_label.config(text=e)
       

def decrypt_process(main_window,text_box, password_entry, status_label,discription_label):
    file_path = text_box.get('1.0', tk.END).strip()  # Get the selected file path
    password = password_entry.get('1.0', tk.END).strip()  # Get the password
   
    if file_path and password:
        status_label.config(text="      Decrypting ...      ",style='info.TLabel', background="", foreground="black")
        discription_label.config(text="                                                                                     ")  
        main_window.update_idletasks()  
        decrypted_file_path = file_path.replace('.enc', '')

        try:
            status_label.config(text="")
            status_label.config(text="Decrypting ...",style='info.TLabel', background="", foreground="black")
            decrypt_file(file_path, password, decrypted_file_path)  # Call decrypt_file function
            status_label.config(text=f"Successful !", style='info.TLabel', background="", foreground="green")  # Update label upon success
            discription_label.config(text=f"Decrypted file: {decrypted_file_path}")
            print("File decrypted successfully.")
        except Exception as e:
            status_label.config(text="Decryption failed !", background="", foreground="red")  # Update label if decryption fails
            print(f"Decryption failed: {e}")
            discription_label.config(text="Please check you selected the correct file and the key.")

def open_main_window():
    main_window = ttk.Window()
    main_window.configure(bg="#00245A")
    main_window.title("SafeSerpent")
    main_window.iconbitmap('./_internal/logo.ico')
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
    file_button.config(padding=(10, 5))
    
    file_frame.pack(pady=5)

    password_frame = ttk.Frame(tab1)
    password_label = ttk.Label(password_frame, text="  Your Key:", font=("Arial", 15))
    password_label.pack(side=tk.LEFT, padx=5, pady=5)
    
    password_entry = ttk.Text(password_frame, height=1, width=50)
    password_entry.pack(side=tk.LEFT, padx=10, pady=5)
    password_button = ttk.Button(password_frame, text="Create Key", command=lambda: generate_key(password_entry))
    password_button.pack(side=tk.LEFT, padx=0, pady=5)
    password_button.config(padding=(10, 5))
    password_frame.pack(pady=5)
    

    encrypt_button = ttk.Button(tab1, text="Encrypt",bootstyle=SUCCESS,  command=lambda: encrypt_process(main_window,text_box, password_entry,status_label,discription_label))
    encrypt_button.pack(pady=20)
    encrypt_button.config(padding=(10, 5))

    status_label = ttk.Label(tab1, text="", font=("Arial", 15), style='info.TLabel')
    status_label.pack(pady=5) 
    discription_label = ttk.Label(tab1, text="", font=("Arial", 10))
    discription_label.pack(pady=5)
    style = ttk.Style()
    style.configure("Custom.TFrame", background="white")

#decryption
    tab2 = ttk.Frame(tab_control)
    tab_control.pack(expand=1, fill='both')
    tab_control.add(tab2, text='Decryption')
    topic2 = ttk.Label(tab2, text=" Decrypt Your File", font=("Arial", 24),style='info.TLabel', )
    topic2.pack(pady=30)

    file_frame2 = ttk.Frame(tab2)
    file_label2 = ttk.Label(file_frame2, text="Select File: ", font=("Arial", 15))
    file_label2.pack(side=tk.LEFT, padx=5, pady=5)
    
    text_box2 = ttk.Text(file_frame2, height=1, width=50)
    text_box2.pack(side=tk.LEFT, padx=5, pady=5)
    
    file_button2 = ttk.Button(file_frame2, text="Browse", command=lambda: select_file(text_box2))
    file_button2.pack(side=tk.LEFT, padx=5, pady=5)
    file_button2.config(padding=(10, 5))
    
    file_frame2.pack(pady=5)

    password_frame2 = ttk.Frame(tab2)
    password_label2 = ttk.Label(password_frame2, text="  Your Key:", font=("Arial", 15))
    password_label2.pack(side=tk.LEFT, padx=5, pady=5)
    
    password_entry2 = ttk.Text(password_frame2, height=1, width=50)
    password_entry2.pack(side=tk.LEFT, padx=10, pady=5)

    password_button2 = ttk.Button(password_frame2, text="",  state='disabled')
    password_button2.pack(side=tk.LEFT, padx=0, pady=5)
    password_button2.config(padding=(10, 5))
    
    password_frame2.pack(pady=5)
    

    decrypt_button = ttk.Button(tab2, text="Decrypt",  command=lambda: decrypt_process(main_window,text_box2, password_entry2,status_label2,discription_label2))
    decrypt_button.pack(pady=20)
    decrypt_button.pack(pady=5)


    status_label2 = ttk.Label(tab2, text="", font=("Arial", 15), style='info.TLabel')
    status_label2.pack(pady=5) 
    discription_label2 = ttk.Label(tab2, text="", font=("Arial", 10))
    discription_label2.pack(pady=5)
    style = ttk.Style()
    style.configure("Custom.TFrame", background="white")

    main_window.mainloop()

# Function to open the loading page
def open_loading_page():
    loading_page = ttk.Window(themename="superhero")
    loading_page.configure(bg="#00245A")
    loading_page.title("SafeSerpent")
    loading_page.iconbitmap('./_internal/logo.ico')
    loading_page.geometry('800x600')
    loading_page.resizable(False, False)

    img = Image.open('./_internal/logo.png')
    img = img.resize((400, 400))
    image = ImageTk.PhotoImage(img)

    image_label = tk.Label(loading_page, image=image)
    image_label.pack(expand=True, pady=10)

    software_name = ttk.Label(loading_page, text="SafeSerpent", font=("Arial", 32))
    software_name.pack(pady=5)

    label = ttk.Label(loading_page, text="Loading ...",style='primary.TLabel', font=("Arial", 15))
    label.pack(pady=5)

    progressbar_frame = ttk.Frame(loading_page, borderwidth=2, relief="groove")
    progressbar_frame.pack(pady=5)

    progressbar = ttk.Progressbar(progressbar_frame, mode="indeterminate", length=200)
    progressbar.pack(pady=5)
    
    def update_progress():
        bartime = 0
        value = 0
        tag = 0
        random_number = random.randint(120, 240)
        print(random_number)
        while bartime <= random_number:
            progressbar["value"] = value
            bartime += 1
            if value >= 0:
                tag = 0
            else:
                tag = 1
            if tag == 0:
                value += 1
            else:
                value -= 1
            time.sleep(0.01)
            progressbar.update()

    update_progress()

    threading.Thread(target=loading, args=(loading_page,)).start()

    loading_page.mainloop()

    open_main_window()

open_loading_page()
