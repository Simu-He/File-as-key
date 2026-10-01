import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from ui.main_window import MainWindow
from ui.workers import CryptoController


APP_NAME = "FAK 文件加密工具"
APP_VERSION = "1.0.0"
ORGANIZATION_NAME = "FAK Tool"


def get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)

    return Path(__file__).resolve().parent


def get_resource_path(*parts: str) -> Path:
    return get_base_dir() / "resources" / Path(*parts)


def load_stylesheet(app: QApplication) -> None:
    style_file = get_resource_path("style.qss")

    if not style_file.exists():
        return

    try:
        stylesheet = style_file.read_text(
            encoding="utf-8"
        )

        app.setStyleSheet(stylesheet)

    except OSError as e:
        print(
            f"无法加载样式文件: {e}",
            file=sys.stderr
        )


def load_application_icon(app: QApplication) -> None:
    icon_file = get_resource_path(
        "icons",
        "app.ico"
    )

    if not icon_file.exists():
        return

    app.setWindowIcon(
        QIcon(str(icon_file))
    )


def create_application() -> QApplication:
    app = QApplication(sys.argv)

    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(ORGANIZATION_NAME)

    app.setQuitOnLastWindowClosed(True)

    load_application_icon(app)
    load_stylesheet(app)

    return app


def main() -> int:

    app = create_application()

    window = MainWindow()

    # 非常重要
    # 必须创建 Controller，
    # MainWindow 的 encrypt_requested / decrypt_requested
    # 才有人接收。
    controller = CryptoController(
        window
    )

    window.show()

    exit_code = app.exec()

    controller.shutdown()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())