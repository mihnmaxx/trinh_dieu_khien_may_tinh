import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QLabel, 
                             QSpinBox, QColorDialog, QFileDialog, QMessageBox, QFontDialog, QListWidget, QInputDialog, QDialog)
from PyQt5.QtGui import QPixmap, QPainter, QColor, QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from tool_main import create_product_label, process_file
import json

class PositionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Điều chỉnh vị trí phần tử")
        layout = QVBoxLayout()

        # Tạo các điều khiển cho từng phần tử
        self.createPositionControls(layout, "Tên sản phẩm")
        self.createPositionControls(layout, "Mã hàng")
        self.createPositionControls(layout, "Mã vạch")

        # Nút OK và Cancel
        buttonLayout = QHBoxLayout()
        okButton = QPushButton("OK")
        okButton.clicked.connect(self.accept)
        cancelButton = QPushButton("Cancel")
        cancelButton.clicked.connect(self.reject)
        buttonLayout.addWidget(okButton)
        buttonLayout.addWidget(cancelButton)
        layout.addLayout(buttonLayout)

        self.setLayout(layout)

    def createPositionControls(self, layout, elementName):
        elementLayout = QHBoxLayout()
        elementLayout.addWidget(QLabel(f"{elementName} X:"))
        xSpin = QSpinBox()
        xSpin.setRange(0, 2000)
        elementLayout.addWidget(xSpin)
        elementLayout.addWidget(QLabel(f"{elementName} Y:"))
        ySpin = QSpinBox()
        ySpin.setRange(0, 2000)
        elementLayout.addWidget(ySpin)
        layout.addLayout(elementLayout)
        setattr(self, f"{elementName.lower().replace(' ', '_')}_x", xSpin)
        setattr(self, f"{elementName.lower().replace(' ', '_')}_y", ySpin)

class LabelDesigner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.loadConfig()

    def initUI(self):
        self.setWindowTitle('Tool Làm Nhãn Dán - Thiết kế Nâng cao')
        self.setGeometry(100, 100, 1000, 700)

        mainLayout = QHBoxLayout()
        
        # Khu vực xem trước
        self.previewLabel = QLabel()
        self.previewLabel.setFixedSize(500, 400)
        self.previewLabel.setStyleSheet("border: 1px solid black;")
        
        # Khu vực điều khiển
        controlLayout = QVBoxLayout()
        
        # Kích thước nhãn
        sizeLayout = QHBoxLayout()
        sizeLayout.addWidget(QLabel("Kích thước:"))
        self.widthSpin = QSpinBox()
        self.widthSpin.setRange(100, 2000)
        self.heightSpin = QSpinBox()
        self.heightSpin.setRange(100, 2000)
        sizeLayout.addWidget(self.widthSpin)
        sizeLayout.addWidget(self.heightSpin)
        controlLayout.addLayout(sizeLayout)
        
        # Màu nền
        self.bgColorButton = QPushButton("Chọn màu nền")
        self.bgColorButton.clicked.connect(self.chooseBgColor)
        controlLayout.addWidget(self.bgColorButton)
        
        # Font chữ
        self.fontButton = QPushButton("Chọn font chữ")
        self.fontButton.clicked.connect(self.chooseFont)
        controlLayout.addWidget(self.fontButton)
        
        # Vị trí các phần tử
        self.positionButton = QPushButton("Điều chỉnh vị trí phần tử")
        self.positionButton.clicked.connect(self.adjustPositions)
        controlLayout.addWidget(self.positionButton)
        
        # Lưu và tải mẫu
        self.saveTemplateButton = QPushButton("Lưu mẫu thiết kế")
        self.saveTemplateButton.clicked.connect(self.saveTemplate)
        self.loadTemplateButton = QPushButton("Tải mẫu thiết kế")
        self.loadTemplateButton.clicked.connect(self.loadTemplate)
        controlLayout.addWidget(self.saveTemplateButton)
        controlLayout.addWidget(self.loadTemplateButton)
        
        # Nút lưu và tạo nhãn
        self.saveButton = QPushButton("Lưu cấu hình")
        self.saveButton.clicked.connect(self.saveConfig)
        self.createButton = QPushButton("Tạo nhãn hàng loạt")
        self.createButton.clicked.connect(self.createLabels)
        self.openMainToolButton = QPushButton("Mở Tool Chính")
        self.openMainToolButton.clicked.connect(self.openMainTool)
        controlLayout.addWidget(self.saveButton)
        controlLayout.addWidget(self.createButton)
        controlLayout.addWidget(self.openMainToolButton)
        
        mainLayout.addWidget(self.previewLabel)
        mainLayout.addLayout(controlLayout)
        
        centralWidget = QWidget()
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)

    def loadConfig(self):
        try:
            with open('config.json', 'r') as f:
                config = json.load(f)
            self.widthSpin.setValue(config['image_size'][0])
            self.heightSpin.setValue(config['image_size'][1])
            self.bgColor = QColor(config['background_color'])
            self.font = QFont(config.get('font', 'Arial'))
            self.positions = config.get('positions', {})
        except:
            self.bgColor = QColor('white')
            self.font = QFont('Arial')
            self.positions = {}
        self.updatePreview()

    def chooseBgColor(self):
        color = QColorDialog.getColor()
        if color.isValid():
            self.bgColor = color
            self.updatePreview()

    def chooseFont(self):
        font, ok = QFontDialog.getFont()
        if ok:
            self.font = font
            self.updatePreview()

    def adjustPositions(self):
        dialog = PositionDialog(self)
        if dialog.exec_():
            self.positions = {
                'ten_san_pham': (dialog.ten_san_pham_x.value(), dialog.ten_san_pham_y.value()),
                'ma_hang': (dialog.ma_hang_x.value(), dialog.ma_hang_y.value()),
                'ma_vach': (dialog.ma_vach_x.value(), dialog.ma_vach_y.value())
            }
            self.updatePreview()
        pass

    def saveTemplate(self):
        name, ok = QInputDialog.getText(self, 'Lưu mẫu', 'Nhập tên mẫu:')
        if ok:
            template = self.getCurrentConfig()
            with open(f'{name}.json', 'w') as f:
                json.dump(template, f)

    def loadTemplate(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Chọn mẫu thiết kế", "", "JSON Files (*.json)")
        if file_name:
            with open(file_name, 'r') as f:
                template = json.load(f)
            self.applyConfig(template)

    def updatePreview(self):
        pixmap = QPixmap(self.widthSpin.value(), self.heightSpin.value())
        pixmap.fill(self.bgColor)
        painter = QPainter(pixmap)
        painter.setFont(self.font)
        painter.drawText(pixmap.rect(), Qt.AlignCenter, "Xem trước nhãn")
        painter.end()
        self.previewLabel.setPixmap(pixmap.scaled(500, 400, Qt.KeepAspectRatio))

    def saveConfig(self):
        config = self.getCurrentConfig()
        with open('config.json', 'w') as f:
            json.dump(config, f)
        print("Đã lưu cấu hình")

    def getCurrentConfig(self):
        return {
            'image_size': [self.widthSpin.value(), self.heightSpin.value()],
            'background_color': self.bgColor.name(),
            'font': self.font.toString(),
            'positions': self.positions
        }

    def applyConfig(self, config):
        self.widthSpin.setValue(config['image_size'][0])
        self.heightSpin.setValue(config['image_size'][1])
        self.bgColor = QColor(config['background_color'])
        self.font.fromString(config['font'])
        self.positions = config.get('positions', {})
        self.updatePreview()

    def createLabels(self):
        file_path = QFileDialog.getOpenFileName(self, 'Chọn file Excel hoặc CSV', '', 'Excel Files (*.xlsx);;CSV Files (*.csv)')[0]
        if file_path:
            save_folder = QFileDialog.getExistingDirectory(self, 'Chọn thư mục lưu nhãn')
            if save_folder:
                config = self.getCurrentConfig()
                self.labelCreationThread = LabelCreationThread(file_path, save_folder, config)
                self.labelCreationThread.finished.connect(self.onLabelCreationFinished)
                self.labelCreationThread.start()

    def onLabelCreationFinished(self):
        QMessageBox.information(self, 'Hoàn thành', 'Đã tạo xong nhãn hàng loạt!')

    def openMainTool(self):
        import tool_main
        tool_main.main()

class LabelCreationThread(QThread):
    finished = pyqtSignal()

    def __init__(self, file_path, save_folder, config):
        super().__init__()
        self.file_path = file_path
        self.save_folder = save_folder
        self.config = config

    def run(self):
        process_file(self.file_path, self.save_folder, self.config)
        self.finished.emit()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    designer = LabelDesigner()
    designer.show()
    sys.exit(app.exec_())