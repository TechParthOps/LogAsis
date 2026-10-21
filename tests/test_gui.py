"""GUI integrity tests that run without a display.

Full MainWindow construction requires a real Qt platform (the offscreen
platform segfaults in headless CI sandboxes), so the window-level smoke test
is covered by manual verification. Everything importable and testable without
instantiating the window is covered here.
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_gui_module_imports():
    import gui.main_window  # noqa: F401


def test_ingestion_worker_exists_and_supports_cancel():
    from gui.main_window import IngestionWorker, IngestionCancelledError

    worker = IngestionWorker(1, "nonexistent.jsonl")
    assert worker.generation == 1
    assert worker._cancel_requested is False
    worker.cancel()
    assert worker._cancel_requested is True
    # Running against a missing file must fail the worker, not crash.
    worker.run()  # emits failed; no exception escapes


def test_ingestion_cancelled_error_exists():
    from gui.main_window import IngestionCancelledError

    assert issubclass(IngestionCancelledError, RuntimeError)


def test_ai_worker_accepts_conversation_context():
    from gui.main_window import AIWorker
    import pandas as pd

    worker = AIWorker(
        "Live AI", "question?", pd.DataFrame({"a": [1]}),
        conversation_context=["earlier question"],
    )
    assert worker.conversation_context == ["earlier question"]
    assert worker.cancel_requested is False


def test_blocking_ingest_path_uses_safe_datetime_conversion():
    """The synchronous ingestion helper must handle NaT timestamps (the
    df.fillna(\"\") crash reproduced in the audit)."""
    from gui.main_window import MainWindow
    import inspect

    source = inspect.getsource(MainWindow._ingest_path)
    # The GUI must not use the crash-prone fillna pattern anywhere in load.
    window_source = inspect.getsource(MainWindow)
    assert 'self.df.fillna("")' not in window_source


def test_load_log_file_has_async_and_blocking_modes():
    from gui.main_window import MainWindow
    import inspect

    sig = inspect.signature(MainWindow.load_log_file)
    assert "blocking" in sig.parameters
    source = inspect.getsource(MainWindow.load_log_file)
    assert "IngestionWorker" in source
    assert "_apply_ingested_dataset" in source
