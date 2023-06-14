import sys
import time
from server.server import Server
from PyQt5.QtCore import QObject, pyqtSignal, QEventLoop, QTimer
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtGui import QTextCursor

# 界面文件
from ui.server_ui import *

stdout_temp = sys.stdout

class Stream(QObject):
    """Redirects console output to text widget."""
    newText = pyqtSignal(str)
 
    def write(self, text):
        self.newText.emit(str(text))
        QApplication.processEvents()


class CustomUI(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(CustomUI, self).__init__(parent)
        self.setupUi(self)
        sys.stdout = Stream(newText=self.onUpdateText)

    def onUpdateText(self, text):
        """Write console output to text widget."""
        cursor = self.textEdit.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        self.textEdit.setTextCursor(cursor)
        self.textEdit.ensureCursorVisible()

    def closeEvent(self, event):
        sys.stdout = stdout_temp #将stdout设置回去
        super().closeEvent(event)
    
        
    def push_button_click(self):#启动
        
        self.server = Server(int(self.spinBox.value()))
        self.server.loop.run_until_complete(self.server.start())

    def push_button2_click(self):#关闭
        self.server.loop.close()

    
        



if __name__ == '__main__':
    app = QApplication(sys.argv)
    cutomUI = CustomUI()
    cutomUI.show()
    sys.exit(app.exec_())
        
'''if __name__ == "__main__":
    
    
    server = Server(64774)
    server.loop.run_until_complete(server.start())'''