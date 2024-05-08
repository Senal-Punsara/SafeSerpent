import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtGui import QIcon

def window():
    app = QApplication(sys.argv)
    win = QMainWindow()
    win.setGeometry(1200,300,500,500)
    win.setWindowTitle("SafeSerpent")
    win.setWindowIcon(QIcon("logo/logo3.jpeg"))
    win.show()
    sys.exit(app.exec_())

window()