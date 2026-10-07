from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QPushButton, QVBoxLayout
)

from ai.provider_config import LiveAIConfig, LIVE_AI_DEFAULTS, load_live_config, save_live_config, get_api_key
from ai.providers import AIProviderError, LiveAIProvider, list_live_models


class LiveAIConfigDialog(QDialog):
    """Configure a live provider and discover its current model catalog.

    Model names are never treated as a permanent LogAsis catalog. The provider
    API is authoritative and the user can refresh the list at any time.
    """

    PROVIDERS = ["OpenAI", "Google Gemini", "NVIDIA NIM", "OpenAI-Compatible"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Live AI Configuration")
        self.setMinimumWidth(650)
        self.saved = False
        self._stored_key = get_api_key() or ""
        self._current_config = load_live_config()

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Configure a live LLM provider. API keys are stored in Windows Credential Manager. "
            "Models are discovered directly from the selected provider API, so the list stays current "
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
        self.model.setToolTip("Models returned by the provider API. Click Refresh Models after changing the API key/provider.")
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
        # catalog immediately. The key is never copied into the UI field.
        if self._stored_key and self._current_config.configured:
            self.refresh_models(silent=True)

    def _provider_changed(self, name: str, use_current=None):
        current = use_current if use_current and use_current.provider == name else None
        default_model, default_endpoint = LIVE_AI_DEFAULTS[name]
        self.endpoint.setText(current.base_url if current and current.base_url else default_endpoint)

        self.model.blockSignals(True)
        self.model.clear()
        if current and current.model:
            # Keep the previously saved model visible until the live catalog is
            # refreshed; Test Connection/Save will verify that it is still
            # provider-supported. Do not inject a permanent cloud model when
            # configuring a provider for the first time.
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

    def _populate_models(self, models, preferred: str = ""):
        ids = [m.id for m in models if getattr(m, "id", "")]
        if not ids:
            raise AIProviderError("The provider returned no selectable chat models.")
        selected = preferred if preferred in ids else (ids[0] if ids else "")
        self.model.blockSignals(True)
        self.model.clear()
        self.model.addItems(ids)
        if selected:
            self.model.setCurrentText(selected)
        self.model.blockSignals(False)
        self.model_status.setText(f"{len(ids)} model(s) discovered")

    def refresh_models(self, silent: bool = False):
        key = self._key()
        if not key:
            self.model_status.setText("API key required")
            if not silent:
                QMessageBox.warning(self, "Missing API Key", "Enter the API key before refreshing the model list.")
            return False
        config = self._candidate()
        if not config.base_url:
            self.model_status.setText("Endpoint required")
            if not silent:
                QMessageBox.warning(self, "Incomplete Configuration", "Enter the provider API endpoint first.")
            return False

        self.refresh_models_btn.setEnabled(False)
        try:
            models = list_live_models(config, key)
            preferred = config.model
            self._populate_models(models, preferred=preferred)
            return True
        except Exception as exc:
            self.model_status.setText("Model discovery failed")
            if not silent:
                QMessageBox.critical(self, "Model Discovery Failed", str(exc))
            return False
        finally:
            self.refresh_models_btn.setEnabled(True)

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
                if config.model not in ids:
                    raise AIProviderError(
                        f"Selected model '{config.model}' is not present in the provider's current model list. "
                        "Click Refresh Models and select an available model."
                    )
                self._populate_models(models, preferred=config.model)

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
