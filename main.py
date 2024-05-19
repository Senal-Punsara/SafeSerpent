# main.py
from PyQt5.QtWidgets import QApplication, QMainWindow
import tkinter as tk
from tkinter import ttk

root = tk.Tk()
root.title("Progress Bar in Tk")
progressbar = ttk.Progressbar(mode="indeterminate")
progressbar.place(x=30, y=60, width=200)
# Start moving the indeterminate progress bar.
progressbar.start()
root.geometry("300x200")
root.mainloop()

