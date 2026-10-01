from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFileDialog,
    QFrame,
    QProgressBar,
    QSizePolicy,
    QMessageBox,
)


# ============================================================
# 工具函数
# ============================================================

def format_file_size(size: int) -> str:
    """
    将文件大小转换为易读格式。
    """

    units = ["B", "KB", "MB", "GB", "TB"]

    value = float(size)

    for unit in units:

        if value < 1024 or unit == units[-1]:

            if unit == "B":
                return f"{int(value)} {unit}"

            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{size} B"


# ============================================================
# 通用文件拖拽框
# ============================================================

class FileDropArea(QFrame):
    """
    通用文件拖拽区域。

    可用于：
    - Payload 文件
    - Key 文件
    """

    file_dropped = Signal(str)
    clicked = Signal()

    def __init__(
        self,
        title: str,
        description: str,
        button_text: str,
        object_name: str,
        parent=None
    ):
        super().__init__(parent)

        self.setAcceptDrops(True)

        self.setObjectName(
            object_name
        )

        self.setMinimumHeight(
            135
        )

        self.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed
        )

        self._build_ui(
            title,
            description,
            button_text
        )

    # ========================================================
    # UI
    # ========================================================

    def _build_ui(
        self,
        title: str,
        description: str,
        button_text: str
    ):
        layout = QVBoxLayout(
            self
        )

        layout.setContentsMargins(
            20,
            16,
            20,
            16
        )

        layout.setSpacing(
            6
        )

        layout.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        # ----------------------------------------------------
        # +
        # ----------------------------------------------------

        self.icon_label = QLabel(
            "＋"
        )

        self.icon_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.icon_label.setObjectName(
            "dropIcon"
        )

        # ----------------------------------------------------
        # 标题
        # ----------------------------------------------------

        self.title_label = QLabel(
            title
        )

        self.title_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.title_label.setObjectName(
            "dropTitle"
        )

        # ----------------------------------------------------
        # 说明
        # ----------------------------------------------------

        self.description_label = QLabel(
            description
        )

        self.description_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.description_label.setObjectName(
            "dropDescription"
        )

        # ----------------------------------------------------
        # 选择按钮
        # ----------------------------------------------------

        self.select_button = QPushButton(
            button_text
        )

        self.select_button.setObjectName(
            "selectFileButton"
        )

        self.select_button.clicked.connect(
            self.clicked.emit
        )

        # ----------------------------------------------------
        # Layout
        # ----------------------------------------------------

        layout.addWidget(
            self.icon_label
        )

        layout.addWidget(
            self.title_label
        )

        layout.addWidget(
            self.description_label
        )

        layout.addWidget(
            self.select_button,
            alignment=Qt.AlignmentFlag.AlignCenter
        )

    # ========================================================
    # Drag & Drop
    # ========================================================

    def dragEnterEvent(
        self,
        event: QDragEnterEvent
    ):
        if not self.isEnabled():
            event.ignore()
            return

        mime_data = event.mimeData()

        if mime_data.hasUrls():

            urls = mime_data.urls()

            if any(
                url.isLocalFile()
                for url in urls
            ):
                event.acceptProposedAction()
                return

        event.ignore()

    def dropEvent(
        self,
        event: QDropEvent
    ):
        if not self.isEnabled():
            event.ignore()
            return

        urls = event.mimeData().urls()

        for url in urls:

            if not url.isLocalFile():
                continue

            path = Path(
                url.toLocalFile()
            )

            if path.is_file():

                self.file_dropped.emit(
                    str(path)
                )

                event.acceptProposedAction()
                return

        event.ignore()


# ============================================================
# 主窗口
# ============================================================

class MainWindow(QMainWindow):

    # ========================================================
    # Worker Signals
    # ========================================================

    encrypt_requested = Signal(
        str,
        str
    )

    decrypt_requested = Signal(
        str
    )

    # ========================================================
    # Init
    # ========================================================

    def __init__(self):
        super().__init__()

        # 当前文件
        self.payload_path: Path | None = None

        # 当前 Key
        self.key_path: Path | None = None

        # Worker 是否运行中
        self.busy = False

        self._setup_window()
        self._build_ui()
        self._connect_signals()

        self._update_ui_state()

    # ========================================================
    # Window
    # ========================================================

    def _setup_window(self):

        self.setWindowTitle(
            "FAK 文件加密工具"
        )

        self.resize(
            720,
            760
        )

        self.setMinimumSize(
            620,
            680
        )

    # ========================================================
    # Build UI
    # ========================================================

    def _build_ui(self):

        central_widget = QWidget()

        self.setCentralWidget(
            central_widget
        )

        main_layout = QVBoxLayout(
            central_widget
        )

        main_layout.setContentsMargins(
            30,
            22,
            30,
            24
        )

        main_layout.setSpacing(
            14
        )

        # ====================================================
        # ① Payload 文件拖拽框
        # ====================================================

        self.payload_drop_area = FileDropArea(
            title="拖入需要处理的文件",
            description="普通文件用于加密，.fak 文件用于解密",
            button_text="选择文件",
            object_name="payloadDropArea"
        )

        main_layout.addWidget(
            self.payload_drop_area
        )

        # ====================================================
        # ② Payload 文件信息
        # ====================================================

        self.payload_info_frame = QFrame()

        self.payload_info_frame.setObjectName(
            "payloadInfoCard"
        )

        payload_info_layout = QVBoxLayout(
            self.payload_info_frame
        )

        payload_info_layout.setContentsMargins(
            18,
            12,
            18,
            12
        )

        payload_info_layout.setSpacing(
            5
        )

        # ----------------------------------------------------
        # Header
        # ----------------------------------------------------

        payload_header_layout = QHBoxLayout()

        payload_title = QLabel(
            "文件信息"
        )

        payload_title.setObjectName(
            "sectionTitle"
        )

        self.clear_file_button = QPushButton(
            "清除"
        )

        self.clear_file_button.setObjectName(
            "smallButton"
        )

        payload_header_layout.addWidget(
            payload_title
        )

        payload_header_layout.addStretch()

        payload_header_layout.addWidget(
            self.clear_file_button
        )

        # ----------------------------------------------------
        # 文件名
        # ----------------------------------------------------

        self.file_name_label = QLabel(
            "尚未选择文件"
        )

        self.file_name_label.setObjectName(
            "fileName"
        )

        self.file_name_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )

        # ----------------------------------------------------
        # 文件信息
        # ----------------------------------------------------

        self.file_info_label = QLabel(
            "-"
        )

        self.file_info_label.setObjectName(
            "fileInfo"
        )

        payload_info_layout.addLayout(
            payload_header_layout
        )

        payload_info_layout.addWidget(
            self.file_name_label
        )

        payload_info_layout.addWidget(
            self.file_info_label
        )

        main_layout.addWidget(
            self.payload_info_frame
        )

        # ====================================================
        # ③ Key 文件拖拽框
        # ====================================================

        self.key_drop_area = FileDropArea(
            title="拖入 Key 文件",
            description="选择用于文件加密的 Key 文件",
            button_text="选择 Key",
            object_name="keyDropArea"
        )

        main_layout.addWidget(
            self.key_drop_area
        )

        # ====================================================
        # ④ Key 信息
        # ====================================================

        self.key_info_frame = QFrame()

        self.key_info_frame.setObjectName(
            "keyInfoCard"
        )

        key_info_layout = QVBoxLayout(
            self.key_info_frame
        )

        key_info_layout.setContentsMargins(
            18,
            12,
            18,
            12
        )

        key_info_layout.setSpacing(
            5
        )

        # ----------------------------------------------------
        # Header
        # ----------------------------------------------------

        key_header_layout = QHBoxLayout()

        key_title = QLabel(
            "Key 信息"
        )

        key_title.setObjectName(
            "sectionTitle"
        )

        self.clear_key_button = QPushButton(
            "清除"
        )

        self.clear_key_button.setObjectName(
            "smallButton"
        )

        key_header_layout.addWidget(
            key_title
        )

        key_header_layout.addStretch()

        key_header_layout.addWidget(
            self.clear_key_button
        )

        # ----------------------------------------------------
        # Key 文件名
        # ----------------------------------------------------

        self.key_name_label = QLabel(
            "尚未选择 Key 文件"
        )

        self.key_name_label.setObjectName(
            "fileName"
        )

        self.key_name_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )

        # ----------------------------------------------------
        # Fingerprint
        # ----------------------------------------------------

        self.key_fingerprint_label = QLabel(
            "指纹：-"
        )

        self.key_fingerprint_label.setObjectName(
            "fileInfo"
        )

        key_info_layout.addLayout(
            key_header_layout
        )

        key_info_layout.addWidget(
            self.key_name_label
        )

        key_info_layout.addWidget(
            self.key_fingerprint_label
        )

        main_layout.addWidget(
            self.key_info_frame
        )

        # ====================================================
        # 操作按钮
        # ====================================================

        action_layout = QHBoxLayout()

        action_layout.setSpacing(
            12
        )

        self.encrypt_button = QPushButton(
            "加密"
        )

        self.encrypt_button.setObjectName(
            "primaryButton"
        )

        self.encrypt_button.setMinimumHeight(
            44
        )

        self.decrypt_button = QPushButton(
            "解密"
        )

        self.decrypt_button.setObjectName(
            "secondaryButton"
        )

        self.decrypt_button.setMinimumHeight(
            44
        )

        action_layout.addWidget(
            self.encrypt_button
        )

        action_layout.addWidget(
            self.decrypt_button
        )

        main_layout.addLayout(
            action_layout
        )

        # ====================================================
        # 进度条
        # ====================================================

        self.progress_bar = QProgressBar()

        self.progress_bar.setRange(
            0,
            100
        )

        self.progress_bar.setValue(
            0
        )

        self.progress_bar.setTextVisible(
            True
        )

        self.progress_bar.setObjectName(
            "progressBar"
        )

        main_layout.addWidget(
            self.progress_bar
        )

        # ====================================================
        # 状态
        # ====================================================

        status_layout = QHBoxLayout()

        status_title = QLabel(
            "状态："
        )

        status_title.setObjectName(
            "statusTitle"
        )

        self.status_label = QLabel(
            "等待操作"
        )

        self.status_label.setObjectName(
            "statusLabel"
        )

        status_layout.addWidget(
            status_title
        )

        status_layout.addWidget(
            self.status_label
        )

        status_layout.addStretch()

        main_layout.addLayout(
            status_layout
        )

        main_layout.addStretch()

    # ========================================================
    # Signals
    # ========================================================

    def _connect_signals(self):

        # Payload 点击选择
        self.payload_drop_area.clicked.connect(
            self.select_payload_file
        )

        # Payload 拖入
        self.payload_drop_area.file_dropped.connect(
            self.set_payload_file
        )

        # Key 点击选择
        self.key_drop_area.clicked.connect(
            self.select_key_file
        )

        # Key 拖入
        self.key_drop_area.file_dropped.connect(
            self.set_key_file
        )

        # 清除 Payload
        self.clear_file_button.clicked.connect(
            self.clear_payload_file
        )

        # 清除 Key
        self.clear_key_button.clicked.connect(
            self.clear_key_file
        )

        # 加密
        self.encrypt_button.clicked.connect(
            self.request_encrypt
        )

        # 解密
        self.decrypt_button.clicked.connect(
            self.request_decrypt
        )

    # ========================================================
    # Payload 文件
    # ========================================================

    def select_payload_file(self):

        if self.busy:
            return

        filename, _ = QFileDialog.getOpenFileName(
            self,
            "选择需要处理的文件",
            "",
            "所有文件 (*.*)"
        )

        if not filename:
            return

        self.set_payload_file(
            filename
        )

    def set_payload_file(
        self,
        filename: str
    ):

        if self.busy:
            return

        path = Path(
            filename
        )

        # ----------------------------------------------------
        # 检查
        # ----------------------------------------------------

        if not path.exists():

            QMessageBox.warning(
                self,
                "文件不存在",
                "选择的文件已经不存在。"
            )

            return

        if not path.is_file():

            QMessageBox.warning(
                self,
                "无效文件",
                "请选择普通文件，而不是目录。"
            )

            return

        # Payload 与 Key 不能相同
        if (
            self.key_path is not None
            and
            path.resolve()
            ==
            self.key_path.resolve()
        ):

            QMessageBox.warning(
                self,
                "文件无效",
                "处理文件与 Key 文件不能相同。"
            )

            return

        self.payload_path = path

        # ----------------------------------------------------
        # Size
        # ----------------------------------------------------

        try:

            size = (
                path.stat().st_size
            )

            size_text = (
                format_file_size(
                    size
                )
            )

        except OSError:

            size_text = (
                "未知大小"
            )

        # ----------------------------------------------------
        # GUI
        # ----------------------------------------------------

        self.file_name_label.setText(
            path.name
        )

        self.file_name_label.setToolTip(
            str(path)
        )

        # ----------------------------------------------------
        # FAK / 普通文件
        # ----------------------------------------------------

        if self._is_fak_file(
            path
        ):

            self.file_info_label.setText(
                f"{size_text}  ·  FAK 加密文件"
            )

            self.status_label.setText(
                "已选择 FAK 文件，可以进行解密"
            )

        else:

            self.file_info_label.setText(
                f"{size_text}  ·  普通文件"
            )

            if self.key_path is None:

                self.status_label.setText(
                    "已选择文件，请选择 Key 文件"
                )

            else:

                self.status_label.setText(
                    "文件与 Key 已准备完成"
                )

        self.progress_bar.setValue(
            0
        )

        self._update_ui_state()

    def clear_payload_file(self):

        if self.busy:
            return

        self.payload_path = None

        self.file_name_label.setText(
            "尚未选择文件"
        )

        self.file_name_label.setToolTip(
            ""
        )

        self.file_info_label.setText(
            "-"
        )

        self.progress_bar.setValue(
            0
        )

        self.status_label.setText(
            "等待操作"
        )

        self._update_ui_state()

    # ========================================================
    # Key 文件
    # ========================================================

    def select_key_file(self):

        if self.busy:
            return

        filename, _ = QFileDialog.getOpenFileName(
            self,
            "选择 Key 文件",
            "",
            "所有文件 (*.*)"
        )

        if not filename:
            return

        self.set_key_file(
            filename
        )

    def set_key_file(
        self,
        filename: str
    ):
        """
        设置 Key 文件。

        这个函数同时供：
        - 文件选择窗口
        - Drag & Drop

        使用。
        """

        if self.busy:
            return

        path = Path(
            filename
        )

        # ----------------------------------------------------
        # 文件检查
        # ----------------------------------------------------

        if not path.exists():

            QMessageBox.warning(
                self,
                "Key 文件不存在",
                "选择的 Key 文件已经不存在。"
            )

            return

        if not path.is_file():

            QMessageBox.warning(
                self,
                "无效 Key",
                "请选择普通文件作为 Key。"
            )

            return

        # ----------------------------------------------------
        # Payload 与 Key 不能相同
        # ----------------------------------------------------

        if (
            self.payload_path is not None
            and
            path.resolve()
            ==
            self.payload_path.resolve()
        ):

            QMessageBox.warning(
                self,
                "Key 文件无效",
                "Key 文件不能与需要处理的文件相同。"
            )

            return

        # ----------------------------------------------------
        # 保存
        # ----------------------------------------------------

        self.key_path = path

        self.key_name_label.setText(
            path.name
        )

        self.key_name_label.setToolTip(
            str(path)
        )

        # Fingerprint 在 Worker 中计算
        self.key_fingerprint_label.setText(
            "指纹：等待计算"
        )

        # ----------------------------------------------------
        # 状态
        # ----------------------------------------------------

        if (
            self.payload_path is not None
            and
            not self._is_fak_file(
                self.payload_path
            )
        ):

            self.status_label.setText(
                "文件与 Key 已准备完成"
            )

        else:

            self.status_label.setText(
                "Key 文件已选择"
            )

        self._update_ui_state()

    def clear_key_file(self):

        if self.busy:
            return

        self.key_path = None

        self.key_name_label.setText(
            "尚未选择 Key 文件"
        )

        self.key_name_label.setToolTip(
            ""
        )

        self.key_fingerprint_label.setText(
            "指纹：-"
        )

        if (
            self.payload_path is not None
            and
            not self._is_fak_file(
                self.payload_path
            )
        ):

            self.status_label.setText(
                "已选择文件，请选择 Key 文件"
            )

        else:

            self.status_label.setText(
                "等待操作"
            )

        self._update_ui_state()

    # ========================================================
    # Fingerprint
    # ========================================================

    def set_key_fingerprint(
        self,
        fingerprint: str
    ):

        if not fingerprint:

            self.key_fingerprint_label.setText(
                "指纹：-"
            )

            return

        fingerprint = (
            fingerprint.upper()
        )

        grouped = " ".join(
            fingerprint[i:i + 4]
            for i in range(
                0,
                len(fingerprint),
                4
            )
        )

        self.key_fingerprint_label.setText(
            f"指纹：{grouped}"
        )

    # ========================================================
    # Encrypt
    # ========================================================

    def request_encrypt(self):

        if self.busy:
            return

        if self.payload_path is None:

            QMessageBox.warning(
                self,
                "未选择文件",
                "请先选择需要加密的文件。"
            )

            return

        if self._is_fak_file(
            self.payload_path
        ):

            QMessageBox.warning(
                self,
                "文件类型错误",
                "当前选择的是 FAK 文件。\n"
                "如需恢复原文件，请使用“解密”。"
            )

            return

        if self.key_path is None:

            QMessageBox.warning(
                self,
                "未选择 Key",
                "加密文件需要先选择 Key 文件。"
            )

            return

        if (
            self.payload_path.resolve()
            ==
            self.key_path.resolve()
        ):

            QMessageBox.warning(
                self,
                "Key 文件无效",
                "Key 文件不能与需要加密的文件相同。"
            )

            return

        self.status_label.setText(
            "正在准备加密..."
        )

        self.encrypt_requested.emit(
            str(self.payload_path),
            str(self.key_path)
        )

    # ========================================================
    # Decrypt
    # ========================================================

    def request_decrypt(self):

        if self.busy:
            return

        if self.payload_path is None:

            QMessageBox.warning(
                self,
                "未选择文件",
                "请先选择需要解密的 FAK 文件。"
            )

            return

        if not self._is_fak_file(
            self.payload_path
        ):

            QMessageBox.warning(
                self,
                "文件类型错误",
                "解密操作需要选择 .fak 文件。"
            )

            return

        self.status_label.setText(
            "正在准备解密..."
        )

        # 保持当前 workers.py 接口不变
        #
        # 解密时 core 会根据 Fingerprint
        # 自动寻找 Key。
        self.decrypt_requested.emit(
            str(self.payload_path)
        )

    # ========================================================
    # Worker -> GUI
    # ========================================================

    def set_busy(
        self,
        busy: bool
    ):

        self.busy = busy

        self.payload_drop_area.setEnabled(
            not busy
        )

        self.clear_file_button.setEnabled(
            not busy
        )

        self.key_drop_area.setEnabled(
            not busy
        )

        self.clear_key_button.setEnabled(
            not busy
        )

        self._update_ui_state()

    def set_progress(
        self,
        value: int
    ):

        value = max(
            0,
            min(
                100,
                value
            )
        )

        self.progress_bar.setValue(
            value
        )

    def set_status(
        self,
        message: str
    ):

        self.status_label.setText(
            message
        )

    # ========================================================
    # Finished
    # ========================================================

    def operation_finished(
        self,
        output_file: str
    ):

        self.set_busy(
            False
        )

        self.progress_bar.setValue(
            100
        )

        output_path = Path(
            output_file
        )

        self.status_label.setText(
            f"操作完成：{output_path.name}"
        )

        QMessageBox.information(
            self,
            "操作完成",
            (
                "文件处理成功。\n\n"
                "输出文件：\n"
                f"{output_path}"
            )
        )

    # ========================================================
    # Failed
    # ========================================================

    def operation_failed(
        self,
        error_message: str
    ):

        self.set_busy(
            False
        )

        self.progress_bar.setValue(
            0
        )

        self.status_label.setText(
            "操作失败"
        )

        QMessageBox.critical(
            self,
            "操作失败",
            error_message
        )

    # ========================================================
    # UI 状态
    # ========================================================

    def _update_ui_state(self):

        # ----------------------------------------------------
        # Busy
        # ----------------------------------------------------

        if self.busy:

            self.encrypt_button.setEnabled(
                False
            )

            self.decrypt_button.setEnabled(
                False
            )

            self.payload_drop_area.setEnabled(
                False
            )

            self.key_drop_area.setEnabled(
                False
            )

            self.clear_file_button.setEnabled(
                False
            )

            self.clear_key_button.setEnabled(
                False
            )

            return

        # ----------------------------------------------------
        # 恢复 Payload
        # ----------------------------------------------------

        self.payload_drop_area.setEnabled(
            True
        )

        self.clear_file_button.setEnabled(
            True
        )

        # ----------------------------------------------------
        # 没有 Payload
        # ----------------------------------------------------

        if self.payload_path is None:

            self.encrypt_button.setEnabled(
                False
            )

            self.decrypt_button.setEnabled(
                False
            )

            self.key_drop_area.setEnabled(
                True
            )

            self.key_info_frame.setEnabled(
                True
            )

            self.clear_key_button.setEnabled(
                True
            )

            return

        # ----------------------------------------------------
        # FAK 文件
        # ----------------------------------------------------

        if self._is_fak_file(
            self.payload_path
        ):

            self.encrypt_button.setEnabled(
                False
            )

            self.decrypt_button.setEnabled(
                True
            )

            # 当前解密逻辑是根据 Fingerprint 自动寻找 Key。
            #
            # 因此 FAK 模式下不要求用户手动指定 Key。
            self.key_drop_area.setEnabled(
                False
            )

            self.key_info_frame.setEnabled(
                False
            )

            return

        # ----------------------------------------------------
        # 普通文件
        # ----------------------------------------------------

        self.decrypt_button.setEnabled(
            False
        )

        self.key_drop_area.setEnabled(
            True
        )

        self.key_info_frame.setEnabled(
            True
        )

        self.clear_key_button.setEnabled(
            True
        )

        self.encrypt_button.setEnabled(
            self.key_path is not None
        )

    # ========================================================
    # Helpers
    # ========================================================

    @staticmethod
    def _is_fak_file(
        path: Path
    ) -> bool:

        return (
            path.suffix.lower()
            == ".fak"
        )