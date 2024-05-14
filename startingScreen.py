

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QIcon

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(230, 360, 331, 71))
        font = QtGui.QFont()
        font.setPointSize(32)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setScaledContents(False)
        self.label.setAlignment(QtCore.Qt.AlignJustify|QtCore.Qt.AlignVCenter)
        self.label.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.label.setObjectName("label")
        self.progressBar = QtWidgets.QProgressBar(self.centralwidget)
        self.progressBar.setGeometry(QtCore.QRect(270, 480, 261, 31))
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        self.progressBar.setFont(font)
        self.progressBar.setProperty("value", 0)  # Initial value set to 0
        self.progressBar.setObjectName("progressBar")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(240, 70, 301, 261))
        self.label_2.setText("")
        self.label_2.setPixmap(QtGui.QPixmap("logo/logo3.jpeg"))
        self.label_2.setScaledContents(True)
        self.label_2.setObjectName("label_2")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        # print("hi")
        # # Create a QTimer object
        # self.timer = QtCore.QTimer()
        # self.timer.timeout.connect(updateProgress)  # Connect timeout signal to updateProgress function
        # self.timer.start(1000)  # Start timer, it will trigger every 1000 milliseconds (1 second)
        # self.counter = 0  # Counter to keep track of seconds
        # print("hi 2")
        # Initialize a QTimer
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(1000)  # Trigger every 1 sec

        # Initialize progress
        self.progress = 0
    
    def update_progress(self):
        self.progress += 25  # Increase progress by 20% every second
        self.progressBar.setValue(self.progress)

        # After 5 seconds (progress reaches 100%), stop the timer and switch page
        if self.progress >= 100:
            self.timer.stop()
            self.switch_page()

    def switch_page(self):
        # Code to switch to another page goes here
        print("another")


    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "SafeSerpent"))
        MainWindow.setWindowIcon(QIcon("logo/logo3.jpeg"))
        self.label.setText(_translate("MainWindow", "SafeSerpent"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
