from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from PySide6.QtCore import (
    QObject,
    QThread,
    Signal,
    Slot,
)

from PySide6.QtWidgets import (
    QFileDialog,
    QMessageBox,
)

from core.crypto import (
    encrypt_file,
    decrypt_file,
    EncryptionResult,
    DecryptionResult,
    OutputFileExistsError,
    KeyFileNotFoundError,
)


# ============================================================
# 类型定义
# ============================================================

TaskMode = Literal[
    "encrypt",
    "decrypt",
]


OutcomeType = Literal[
    "success",
    "error",
    "overwrite_required",
    "key_required",
]


# ============================================================
# Task
# ============================================================

@dataclass(frozen=True)
class CryptoTask:
    """
    一个完整的加密 / 解密任务描述。
    """

    mode: TaskMode

    payload_file: Path

    key_file: Path | None = None

    overwrite: bool = False


# ============================================================
# Worker Result
# ============================================================

@dataclass(frozen=True)
class WorkerOutcome:
    """
    Worker 执行结果。

    kind:

        success
            操作成功。

        error
            发生普通错误。

        overwrite_required
            输出文件已存在，需要 GUI 询问用户。

        key_required
            自动搜索不到 Key，需要 GUI 让用户手动选择。
    """

    kind: OutcomeType

    task: CryptoTask

    result: EncryptionResult | DecryptionResult | None = None

    message: str = ""


# ============================================================
# 进度映射
#
# 注意：
#
# FAK1 当前并不是分块 AES，
# 因此无法得到真正精确的 byte-level 加密进度。
#
# 当前 ProgressBar 表示的是“处理阶段进度”。
# ============================================================

ENCRYPT_PROGRESS = {
    "正在计算 Key 指纹...": 10,
    "正在读取 Key 文件...": 20,
    "正在派生加密密钥...": 35,
    "正在读取需要加密的文件...": 50,
    "正在加密文件...": 70,
    "正在生成 FAK 文件...": 90,
    "加密完成": 100,
}


DECRYPT_PROGRESS = {
    "正在读取 FAK 文件信息...": 5,
    "正在自动寻找 Key 文件...": 15,
    "正在验证指定的 Key 文件...": 15,
    "Key 文件验证通过": 30,
    "正在派生解密密钥...": 40,
    "正在读取加密数据...": 55,
    "正在解密文件...": 75,
    "正在写入解密文件...": 90,
    "解密完成": 100,
}


# ============================================================
# CryptoWorker
# ============================================================

class CryptoWorker(QObject):
    """
    在 QThread 中真正执行 core.crypto。

    Worker 不操作 GUI Widget。

    它只通过 Signal 向主线程报告：
    - 状态
    - 进度
    - 最终结果
    """

    status_changed = Signal(str)

    progress_changed = Signal(int)

    completed = Signal(object)

    def __init__(
        self,
        task: CryptoTask,
        parent=None,
    ):
        super().__init__(parent)

        self.task = task

    # ========================================================
    # Status Callback
    # ========================================================

    def _status_callback(
        self,
        message: str,
    ) -> None:
        """
        接收 core.crypto 的 status_callback。

        然后转换成 Qt Signal。
        """

        self.status_changed.emit(
            message
        )

        progress = self._get_progress(
            message
        )

        if progress is not None:
            self.progress_changed.emit(
                progress
            )

    def _get_progress(
        self,
        message: str,
    ) -> int | None:
        """
        将 crypto.py 的状态文字转换成阶段进度。
        """

        if self.task.mode == "encrypt":

            return ENCRYPT_PROGRESS.get(
                message
            )

        return DECRYPT_PROGRESS.get(
            message
        )

    # ========================================================
    # Run
    # ========================================================

    @Slot()
    def run(self):
        """
        QThread 启动后执行。
        """

        try:

            if self.task.mode == "encrypt":

                self._run_encrypt()

            elif self.task.mode == "decrypt":

                self._run_decrypt()

            else:

                self.completed.emit(
                    WorkerOutcome(
                        kind="error",
                        task=self.task,
                        message=(
                            "未知任务类型："
                            f"{self.task.mode}"
                        ),
                    )
                )

        except Exception as exc:

            # 最终安全网
            #
            # 理论上 _run_encrypt / _run_decrypt
            # 已经会处理常见异常。
            self.completed.emit(
                WorkerOutcome(
                    kind="error",
                    task=self.task,
                    message=str(exc),
                )
            )

    # ========================================================
    # Encrypt
    # ========================================================

    def _run_encrypt(self):
        """
        执行加密。
        """

        if self.task.key_file is None:

            self.completed.emit(
                WorkerOutcome(
                    kind="error",
                    task=self.task,
                    message="加密任务没有指定 Key 文件",
                )
            )

            return

        try:

            result = encrypt_file(
                payload_file=self.task.payload_file,
                key_file=self.task.key_file,
                overwrite=self.task.overwrite,
                status_callback=self._status_callback,
            )

        except OutputFileExistsError as exc:

            self.completed.emit(
                WorkerOutcome(
                    kind="overwrite_required",
                    task=self.task,
                    message=str(exc),
                )
            )

            return

        except Exception as exc:

            self.completed.emit(
                WorkerOutcome(
                    kind="error",
                    task=self.task,
                    message=str(exc),
                )
            )

            return

        self.completed.emit(
            WorkerOutcome(
                kind="success",
                task=self.task,
                result=result,
            )
        )

    # ========================================================
    # Decrypt
    # ========================================================

    def _run_decrypt(self):
        """
        执行解密。
        """

        try:

            result = decrypt_file(
                fak_file=self.task.payload_file,
                key_file=self.task.key_file,
                overwrite=self.task.overwrite,
                status_callback=self._status_callback,
            )

        except KeyFileNotFoundError as exc:

            self.completed.emit(
                WorkerOutcome(
                    kind="key_required",
                    task=self.task,
                    message=str(exc),
                )
            )

            return

        except OutputFileExistsError as exc:

            self.completed.emit(
                WorkerOutcome(
                    kind="overwrite_required",
                    task=self.task,
                    message=str(exc),
                )
            )

            return

        except Exception as exc:

            self.completed.emit(
                WorkerOutcome(
                    kind="error",
                    task=self.task,
                    message=str(exc),
                )
            )

            return

        self.completed.emit(
            WorkerOutcome(
                kind="success",
                task=self.task,
                result=result,
            )
        )


# ============================================================
# CryptoController
# ============================================================

class CryptoController(QObject):
    """
    MainWindow 和 CryptoWorker 之间的控制器。

    负责：

    MainWindow
        ↓
    创建 Task
        ↓
    创建 QThread
        ↓
    启动 Worker
        ↓
    接收 Outcome
        ↓
    更新 MainWindow

    MainWindow 因此不需要知道任何 QThread 细节。
    """

    def __init__(
        self,
        window,
        parent=None,
    ):
        super().__init__(parent)

        self.window = window

        # 当前线程
        self._thread: QThread | None = None

        # 当前 Worker
        self._worker: CryptoWorker | None = None

        # Worker 返回结果
        #
        # 等线程真正结束以后再处理，
        # 避免在旧线程仍未完全退出时启动新线程。
        self._pending_outcome: WorkerOutcome | None = None

        self._connect_window()

    # ========================================================
    # MainWindow Signals
    # ========================================================

    def _connect_window(self):
        """
        接收 MainWindow 发出的操作请求。
        """

        self.window.encrypt_requested.connect(
            self.start_encrypt
        )

        self.window.decrypt_requested.connect(
            self.start_decrypt
        )

    # ========================================================
    # Encrypt
    # ========================================================

    @Slot(str, str)
    def start_encrypt(
        self,
        payload_file: str,
        key_file: str,
    ):
        """
        MainWindow 点击“加密”后进入这里。
        """

        task = CryptoTask(
            mode="encrypt",
            payload_file=Path(
                payload_file
            ),
            key_file=Path(
                key_file
            ),
            overwrite=False,
        )

        self._start_task(
            task
        )

    # ========================================================
    # Decrypt
    # ========================================================

    @Slot(str)
    def start_decrypt(
        self,
        payload_file: str,
    ):
        """
        MainWindow 点击“解密”后进入这里。

        默认：
            key_file=None

        core.crypto 会首先自动寻找 Key。
        """

        task = CryptoTask(
            mode="decrypt",
            payload_file=Path(
                payload_file
            ),
            key_file=None,
            overwrite=False,
        )

        self._start_task(
            task
        )

    # ========================================================
    # QThread
    # ========================================================

    def _start_task(
        self,
        task: CryptoTask,
    ):
        """
        创建并启动后台线程。
        """

        # 防止重复启动
        if (
            self._thread is not None
            and
            self._thread.isRunning()
        ):
            return

        # UI 锁定
        self.window.set_busy(
            True
        )

        self.window.set_progress(
            0
        )

        # ----------------------------------------------------
        # Thread
        # ----------------------------------------------------

        thread = QThread(
            self
        )

        worker = CryptoWorker(
            task
        )

        worker.moveToThread(
            thread
        )

        # ----------------------------------------------------
        # Start
        # ----------------------------------------------------

        thread.started.connect(
            worker.run
        )

        # ----------------------------------------------------
        # Worker -> Window
        # ----------------------------------------------------

        worker.status_changed.connect(
            self.window.set_status
        )

        worker.progress_changed.connect(
            self.window.set_progress
        )

        # ----------------------------------------------------
        # Worker Completed
        # ----------------------------------------------------

        worker.completed.connect(
            self._on_worker_completed
        )

        worker.completed.connect(
            thread.quit
        )

        # ----------------------------------------------------
        # Cleanup
        # ----------------------------------------------------

        thread.finished.connect(
            worker.deleteLater
        )

        thread.finished.connect(
            self._on_thread_finished
        )

        thread.finished.connect(
            thread.deleteLater
        )

        # 必须保存引用，
        # 否则 Python GC 可能提前删除线程对象。
        self._thread = thread
        self._worker = worker

        thread.start()

    # ========================================================
    # Worker Completed
    # ========================================================

    @Slot(object)
    def _on_worker_completed(
        self,
        outcome: WorkerOutcome,
    ):
        """
        Worker 已经完成计算。

        此时先保存结果。

        真正 GUI 处理等待 QThread finished，
        避免立即重新启动线程导致生命周期冲突。
        """

        self._pending_outcome = (
            outcome
        )

    # ========================================================
    # Thread Finished
    # ========================================================

    @Slot()
    def _on_thread_finished(self):
        """
        后台线程完全结束。
        """

        self._thread = None
        self._worker = None

        outcome = (
            self._pending_outcome
        )

        self._pending_outcome = None

        if outcome is None:

            self.window.set_busy(
                False
            )

            return

        self._handle_outcome(
            outcome
        )

    # ========================================================
    # Outcome
    # ========================================================

    def _handle_outcome(
        self,
        outcome: WorkerOutcome,
    ):
        """
        根据 WorkerOutcome 执行 GUI 行为。
        """

        # ----------------------------------------------------
        # Success
        # ----------------------------------------------------

        if outcome.kind == "success":

            self._handle_success(
                outcome
            )

            return

        # ----------------------------------------------------
        # Output 已存在
        # ----------------------------------------------------

        if (
            outcome.kind
            ==
            "overwrite_required"
        ):

            self._handle_overwrite(
                outcome
            )

            return

        # ----------------------------------------------------
        # 找不到 Key
        # ----------------------------------------------------

        if outcome.kind == "key_required":

            self._handle_key_required(
                outcome
            )

            return

        # ----------------------------------------------------
        # 普通错误
        # ----------------------------------------------------

        self.window.operation_failed(
            outcome.message
            or
            "发生未知错误"
        )

    # ========================================================
    # Success
    # ========================================================

    def _handle_success(
        self,
        outcome: WorkerOutcome,
    ):
        """
        成功完成。
        """

        result = outcome.result

        if result is None:

            self.window.operation_failed(
                "程序返回了空结果"
            )

            return

        # ----------------------------------------------------
        # Fingerprint
        # ----------------------------------------------------

        self.window.set_key_fingerprint(
            result.key_fingerprint.hex()
        )

        # ----------------------------------------------------
        # 解密时可以显示实际找到的 Key
        # ----------------------------------------------------

        if isinstance(
            result,
            DecryptionResult
        ):

            self.window.key_name_label.setText(
                result.key_file.name
            )

            self.window.key_name_label.setToolTip(
                str(result.key_file)
            )

        # ----------------------------------------------------
        # Finish
        # ----------------------------------------------------

        self.window.operation_finished(
            str(result.output_file)
        )

    # ========================================================
    # Overwrite
    # ========================================================

    def _handle_overwrite(
        self,
        outcome: WorkerOutcome,
    ):
        """
        输出文件已经存在。

        在 GUI 主线程询问是否覆盖。
        """

        answer = QMessageBox.question(
            self.window,
            "文件已经存在",
            (
                "目标文件已经存在。\n\n"
                "是否覆盖现有文件？"
            ),
            (
                QMessageBox.StandardButton.Yes
                |
                QMessageBox.StandardButton.No
            ),
            QMessageBox.StandardButton.No,
        )

        if (
            answer
            !=
            QMessageBox.StandardButton.Yes
        ):

            self.window.set_busy(
                False
            )

            self.window.set_progress(
                0
            )

            self.window.set_status(
                "操作已取消"
            )

            return

        # ----------------------------------------------------
        # Retry
        # ----------------------------------------------------

        old_task = outcome.task

        new_task = CryptoTask(
            mode=old_task.mode,
            payload_file=old_task.payload_file,
            key_file=old_task.key_file,
            overwrite=True,
        )

        self._start_task(
            new_task
        )

    # ========================================================
    # Manual Key
    # ========================================================

    def _handle_key_required(
        self,
        outcome: WorkerOutcome,
    ):
        """
        自动寻找不到 Key。

        让用户手动选择 Key 文件。
        """

        self.window.set_status(
            "未自动找到 Key 文件"
        )

        answer = QMessageBox.question(
            self.window,
            "未找到 Key 文件",
            (
                "没有在 FAK 文件所在目录找到"
                "匹配的 Key 文件。\n\n"
                "是否手动选择 Key 文件？"
            ),
            (
                QMessageBox.StandardButton.Yes
                |
                QMessageBox.StandardButton.No
            ),
            QMessageBox.StandardButton.Yes,
        )

        if (
            answer
            !=
            QMessageBox.StandardButton.Yes
        ):

            self.window.set_busy(
                False
            )

            self.window.set_progress(
                0
            )

            self.window.set_status(
                "未找到匹配的 Key 文件"
            )

            return

        # ----------------------------------------------------
        # File Dialog
        # ----------------------------------------------------

        filename, _ = (
            QFileDialog.getOpenFileName(
                self.window,
                "选择 Key 文件",
                str(
                    outcome.task
                    .payload_file
                    .parent
                ),
                "所有文件 (*.*)",
            )
        )

        if not filename:

            self.window.set_busy(
                False
            )

            self.window.set_progress(
                0
            )

            self.window.set_status(
                "Key 文件选择已取消"
            )

            return

        # ----------------------------------------------------
        # Retry with manual Key
        # ----------------------------------------------------

        new_task = CryptoTask(
            mode="decrypt",
            payload_file=(
                outcome.task.payload_file
            ),
            key_file=Path(
                filename
            ),
            overwrite=(
                outcome.task.overwrite
            ),
        )

        self._start_task(
            new_task
        )

    # ========================================================
    # Shutdown
    # ========================================================

    def shutdown(self):
        """
        程序退出时安全停止线程。

        当前 AESGCM / Argon2 操作本身无法安全地
        在中途强制终止，因此这里只等待正在运行的
        Worker 正常退出。

        不使用 terminate()，
        因为强制杀死线程可能导致文件写入损坏。
        """

        if self._thread is None:
            return

        if not self._thread.isRunning():
            return

        self._thread.quit()

        self._thread.wait()