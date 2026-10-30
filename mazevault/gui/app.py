"""Entry point. Single instance per user, like the other Maze apps."""
from __future__ import annotations

import ctypes
import os
import sys

from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWidgets import QApplication

from mazevault.core import settings
from mazevault.gui.i18n import set_language
from mazevault.gui.icons import app_logo
from mazevault.gui.theme import stylesheet
from mazevault.gui.window import MainWindow

_RUNTIME_DIR = os.environ.get("XDG_RUNTIME_DIR", "")
_SINGLETON = (os.path.join(_RUNTIME_DIR, "maze-vault-singleton")
              if _RUNTIME_DIR and os.path.isdir(_RUNTIME_DIR)
              else f"maze-vault-singleton-{os.getuid()}")


def _harden_process() -> None:
    """No core dumps, and no ptrace from other processes of the same user:
    with PR_SET_DUMPABLE=0 the kernel refuses to let them read our memory,
    where the unlocked keys live."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(4, 0, 0, 0, 0)   # PR_SET_DUMPABLE, 0
    except (OSError, AttributeError):
        pass


def _install_excepthook(app: QApplication) -> None:
    """PyQt6 aborts the whole process on an exception escaping a slot. A bug
    in one button must never take the app down (or interrupt work on the
    user's data), so log it, tell the user, and keep running."""
    import traceback

    def hook(etype, value, tb) -> None:
        traceback.print_exception(etype, value, tb, file=sys.stderr)
        sys.stderr.flush()
        try:
            from PyQt6.QtWidgets import QMessageBox
            from mazevault.gui.i18n import t
            QMessageBox.warning(app.activeWindow(), app.applicationDisplayName(),
                                f"{etype.__name__}: {value}\n\n{t('bug_body')}")
        except Exception:  # noqa: BLE001 — the hook itself must never raise
            pass
    sys.excepthook = hook


def _activate_running_instance() -> bool:
    sock = QLocalSocket()
    sock.connectToServer(_SINGLETON)
    if sock.waitForConnected(300):
        sock.write(b"show")
        sock.flush()
        sock.waitForBytesWritten(300)
        sock.disconnectFromServer()
        return True
    return False


def run() -> int:
    _harden_process()
    set_language(settings.load()["language"])
    for arg in sys.argv[1:]:
        if arg.startswith("--lang="):
            set_language(arg.split("=", 1)[1])

    app = QApplication(sys.argv)
    app.setApplicationName("Maze Vault")
    app.setApplicationDisplayName("Maze Vault")
    app.setOrganizationName("maze")
    app.setDesktopFileName("maze-vault")
    app.setWindowIcon(app_logo())
    _install_excepthook(app)

    if _activate_running_instance():
        return 0
    QLocalServer.removeServer(_SINGLETON)
    singleton = QLocalServer()
    singleton.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
    singleton.listen(_SINGLETON)

    app.setStyleSheet(stylesheet())
    window = MainWindow()

    def _raise() -> None:
        conn = singleton.nextPendingConnection()
        if conn is not None:
            conn.disconnectFromServer()
        window.showNormal()
        window.raise_()
        window.activateWindow()
    singleton.newConnection.connect(_raise)

    window.show()
    code = app.exec()
    _shutdown(app, window)
    return code


def _shutdown(app: QApplication, window) -> None:
    """Tear down in a fixed order. Left to the garbage collector, a Qt object
    can be destroyed after the QApplication and crash the interpreter on exit."""
    import gc
    from PyQt6.QtCore import QCoreApplication, QEvent, QThreadPool
    QThreadPool.globalInstance().waitForDone(10_000)
    window.hide()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    del window
    gc.collect()
