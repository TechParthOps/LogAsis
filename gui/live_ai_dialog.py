from __future__ import annotations

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QPushButton, QVBoxLayout
)

from ai.provider_config import LiveAIConfig, LIVE_AI_DEFAULTS, load_live_config, save_live_config, get_api_key
from ai.providers import AIProviderError, LiveAIProvider, list_live_models

# Model families that are NOT general chat/investigation models. Providers
# such as NVIDIA NIM list embeddings, rerankers, speech, and safety models in
# the same /models catalog; offering them as the analyst model only confuses
# the user. The exclusion list is conservative: anything not matching stays.
_NON_CHAT_MODEL_HINTS = (
    "embed", "rerank", "content-safety", "content_safety", "aegis", "guard",
    "moderation", "whisper", "riva", "tts", "asr", "speech", "ocr", "clip",
    "diffusion", "sdxl", "stable-diffusion", "nemoretriever", "vila",
    "neva", "opt-", "bloom", "t5", "bert", "robusta", "deplot", "neva",
    "palmyra-creative", "biomedical",
)


def _selectable_chat_models(models) -> list[str]:
    """Filter a provider model catalog down to plausible analyst models."""
    ids: list[str] = []
    for model in models:
        model_id = str(getattr(model, "id", "") or "").strip()
        if not model_id:
            continue
        lowered = model_id.lower()
        if any(hint in lowered for hint in _NON_CHAT_MODEL_HINTS):
            continue
        if model_id not in ids:
            ids.append(model_id)
    return ids


class ModelListWorker(QObject):
    """Fetches the provider's current model catalog off the GUI thread.

    The previous dialog performed the network call synchronously, freezing
    the window for the duration of the request.
    """
    finished = Signal(list, str)   # selectable model ids, saved model
    failed = Signal(str)

    def __init__(self, config: LiveAIConfig, api_key: str, saved_model: str = ""):
        super().__init__()
        self._config = config
        self._api_key = api_key
        self._saved_model = saved_model

    def run(self):
        try:
            models = list_live_models(self._config, self._api_key)
            self.finished.emit(_selectable_chat_models(models), self._saved_model)
        except Exception as exc:
            self.failed.emit(str(exc))


class LiveAIConfigDialog(QDialog):
    """Configure a live provider and discover its current model catalog.

    Model names are never treated as a permanent LogAsis catalog. The provider
    API is authoritative: the combo is populated dynamically from the
    provider's model-list endpoint, so models the provider has removed or
    retired disappear from the selector and users cannot pick a dead model.
    Discovery runs on a background thread so the dialog never freezes.
    """

    PROVIDERS = ["OpenAI", "Google Gemini", "NVIDIA NIM", "OpenAI-Compatible"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Live AI Configuration")
        self.setMinimumWidth(650)
        self.saved = False
        self._stored_key = get_api_key() or ""
        self._current_config = load_live_config()
        self._model_thread = None
        self._model_worker = None
        self._discovered_ids: list[str] = []

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Configure a live LLM provider. API keys are stored in Windows Credential Manager. "
            "Models are discovered automatically from the selected provider API, so the list stays current "
            "when providers add, remove, rename, or retire models."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        self.provider = QComboBox()
        self.provider.addItems(self.PROVIDERS)
        if self._current_config.provider in self.PROVIDERS:
            self.provider.setCurrentText(self._current_config.provider)
        self.provider.currentTextChanged.connect(self._provider_changed)
        form.addRow("Provider:", self.provider)

        self.endpoint = QLineEdit()
        self.endpoint.setPlaceholderText("https://provider.example/v1")
        form.addRow("API Endpoint:", self.endpoint)

        model_row = QHBoxLayout()
        self.model = QComboBox()
        self.model.setMinimumWidth(390)
        self.model.setToolTip("Models currently offered by the provider API. Removed models are dropped automatically.")
        self.model_status = QLabel("Model list not loaded")
        self.model_status.setWordWrap(True)
        self.refresh_models_btn = QPushButton("Refresh Models")
        self.refresh_models_btn.clicked.connect(self.refresh_models)
        model_row.addWidget(self.model, 1)
        model_row.addWidget(self.refresh_models_btn)
        model_row.addWidget(self.model_status, 1)
        form.addRow("Model:", model_row)

        self.api_key = QLineEdit()
        self.api_key.setEchoMode(QLineEdit.Password)
        self.api_key.setPlaceholderText("Paste a new API key; existing key is kept securely if left blank")
        form.addRow("API Key:", self.api_key)
        layout.addLayout(form)

        note = QLabel(
            "NVIDIA NIM, OpenAI, Gemini, and OpenAI-compatible providers use their model-list API for discovery. "
            "Google Gemini still uses its native File API for large-log analysis. For OpenAI-Compatible endpoints, "
            "a custom model can be typed if the server does not expose /models."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        buttons = QHBoxLayout()
        self.test_btn = QPushButton("Test Connection")
        self.test_btn.clicked.connect(self.test_connection)
        buttons.addWidget(self.test_btn)
        buttons.addStretch(1)
        self.box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.box.accepted.connect(self.save)
        self.box.rejected.connect(self.reject)
        buttons.addWidget(self.box)
        layout.addLayout(buttons)

        self._provider_changed(self.provider.currentText(), use_current=self._current_config)

        # If a securely stored key already exists, discover the current model
        # catalog immediately (background thread; the dialog stays responsive).
        if self._stored_key and self._current_config.configured:
            self.refresh_models(silent=True)

    # ------------------------------------------------------------------
    # dynamic model discovery
    # ------------------------------------------------------------------
    def _start_model_worker(self, silent: bool) -> bool:
        if self._model_thread is not None and self._model_thread.isRunning():
            return True  # a discovery request is already in flight
        key = self._key()
        if not key:
            if not silent:
                QMessageBox.warning(self, "Missing API Key", "Enter the API key before refreshing the model list.")
            return False
        config = self._candidate()
        if not config.base_url:
            if not silent:
                QMessageBox.warning(self, "Incomplete Configuration", "Enter the provider API endpoint first.")
            return False

        saved_model = self.model.currentText().strip() or self._current_config.model
        self.refresh_models_btn.setEnabled(False)
        self.model_status.setText("Loading current models from the provider…")

        self._model_thread = QThread(self)
        self._model_worker = ModelListWorker(config, key, saved_model)
        self._model_worker.moveToThread(self._model_thread)
        self._model_thread.started.connect(self._model_worker.run)
        self._model_worker.finished.connect(self._models_discovered)
        self._model_worker.failed.connect(self._models_failed)
        self._model_worker.finished.connect(self._model_thread.quit)
        self._model_worker.failed.connect(self._model_thread.quit)
        self._model_thread.finished.connect(self._model_worker.deleteLater)
        self._model_thread.finished.connect(self._model_thread.deleteLater)
        self._model_thread.finished.connect(self._model_discovery_finished)
        self._model_thread.start()
        return True

    def _models_discovered(self, ids: list, saved_model: str):
        ids = [str(x) for x in ids if str(x).strip()]
        self._discovered_ids = ids
        if not ids:
            self.model_status.setText("The provider returned no selectable chat models.")
            return
        # Only models currently offered by the provider are offered here:
        # removed/retired models disappear from the selector.
        selected = saved_model if saved_model in ids else ""
        note = ""
        if saved_model and not selected:
            # The saved model was removed or renamed by the provider. Pick the
            # closest same-family model when possible, else the first entry,
            # and tell the user plainly.
            family = saved_model.split("/")[0].lower() if "/" in saved_model else saved_model.split("-")[0].lower()
            same_family = [m for m in ids if m.lower().startswith(family)]
            selected = same_family[0] if same_family else ids[0]
            note = f" — saved model '{saved_model}' is no longer offered; selected '{selected}'"
        self.model.blockSignals(True)
        self.model.clear()
        self.model.addItems(ids)
        if selected:
            self.model.setCurrentText(selected)
        self.model.blockSignals(False)
        self.model_status.setText(f"{len(ids)} model(s) currently offered by the provider{note}")

    def _models_failed(self, message: str):
        self.model_status.setText("Model discovery failed — the saved model stays selected")

    def _model_discovery_finished(self):
        self.refresh_models_btn.setEnabled(True)
        self._model_worker = None
        self._model_thread = None

    def refresh_models(self, silent: bool = False):
        """Refresh the model combo from the provider's live catalog.

        Runs on a background thread; the dialog stays responsive.
        """
        return self._start_model_worker(silent=silent)

    # ------------------------------------------------------------------
    # configuration
    # ------------------------------------------------------------------
    def _provider_changed(self, name: str, use_current=None):
        current = use_current if use_current and use_current.provider == name else None
        default_model, default_endpoint = LIVE_AI_DEFAULTS[name]
        self.endpoint.setText(current.base_url if current and current.base_url else default_endpoint)

        self.model.blockSignals(True)
        self.model.clear()
        if current and current.model:
            # Keep the previously saved model visible until the live catalog
            # arrives; discovery then replaces the list with the provider's
            # current models and drops anything the provider removed.
            self.model.addItem(current.model)
        self.model.blockSignals(False)

        # Known providers should select an API-discovered model rather than
        # silently accepting a stale hardcoded model. Custom compatible servers
        # may not implement /models, so their model field remains editable.
        self.model.setEditable(name == "OpenAI-Compatible")
        self.model_status.setText("Refresh to load current models")

        if name == "NVIDIA NIM":
            self.endpoint.setPlaceholderText("https://integrate.api.nvidia.com/v1")
        elif name == "OpenAI-Compatible":
            self.endpoint.setPlaceholderText("Provider's OpenAI-compatible base URL")
        elif name == "Google Gemini":
            self.endpoint.setPlaceholderText("https://generativelanguage.googleapis.com/v1beta/openai")
        else:
            self.endpoint.setPlaceholderText(default_endpoint)

        if self._key():
            self.refresh_models(silent=True)

    def _candidate(self):
        return LiveAIConfig(
            provider=self.provider.currentText(),
            model=self.model.currentText().strip(),
            base_url=self.endpoint.text().strip().rstrip("/"),
            configured=True,
        )

    def _key(self):
        return self.api_key.text().strip() or self._stored_key.strip()

    def test_connection(self):
        key = self._key()
        if not key:
            QMessageBox.warning(self, "Missing API Key", "Enter the API key before testing the connection.")
            return
        config = self._candidate()
        if not config.model or not config.base_url:
            QMessageBox.warning(self, "Incomplete Configuration", "Provider, endpoint and model are required.")
            return
        self.test_btn.setEnabled(False)
        try:
            # First verify that the selected model is still present when the
            # provider exposes /models. This catches retired NVIDIA/OpenAI/etc.
            # models before an inference request is sent.
            if config.provider != "OpenAI-Compatible":
                models = list_live_models(config, key)
                ids = {m.id for m in models}
                selectable = _selectable_chat_models(models)
                if config.model not in ids:
                    raise AIProviderError(
                        f"Selected model '{config.model}' is not present in the provider's current model list. "
                        "Click Refresh Models and select an available model."
                    )
                if config.model not in selectable:
                    raise AIProviderError(
                        f"Selected model '{config.model}' is not usable as the LogAsis analyst model "
                        "(it looks like an embedding/reranking/safety model). Select a chat model."
                    )
                self._models_discovered(selectable, config.model)

            result = LiveAIProvider(config=config, api_key=key).test_connection()
            QMessageBox.information(self, "Connection Successful", f"Provider responded successfully.\n\n{result[:200]}")
        except Exception as exc:
            QMessageBox.critical(self, "Connection Failed", str(exc))
        finally:
            self.test_btn.setEnabled(True)

    def save(self):
        key = self._key()
        if not key:
            QMessageBox.warning(self, "Missing API Key", "Enter the API key before saving.")
            return
        config = self._candidate()
        if not config.base_url:
            QMessageBox.warning(self, "Incomplete Configuration", "Provider and endpoint are required.")
            return
        try:
            if config.provider != "OpenAI-Compatible":
                models = list_live_models(config, key)
                ids = {m.id for m in models}
                if not config.model or config.model not in ids:
                    QMessageBox.warning(
                        self,
                        "Select Current Model",
                        "The selected model is not present in the provider's current model catalog. "
                        "Click Refresh Models and select an available model.",
                    )
                    return
            elif not config.model:
                QMessageBox.warning(self, "Missing Model", "Enter the model name for the OpenAI-compatible endpoint.")
                return
            save_live_config(config, key)
            self.saved = True
            self.accept()
        except Exception as exc:
            QMessageBox.critical(self, "Secure Storage Failed", f"The API key could not be stored securely.\n\n{exc}")
