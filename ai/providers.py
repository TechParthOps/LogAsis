from __future__ import annotations

import json
import hashlib
import mimetypes
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict
from urllib import error, request

from ai.provider_config import LiveAIConfig, get_api_key, load_live_config


class AIProviderError(RuntimeError):
    """Raised when an AI provider cannot be reached or returns an invalid response."""

    def __init__(self, message: str, *, status_code: int | None = None, retry_after: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after

    @property
    def is_rate_limited(self) -> bool:
        return self.status_code == 429


def _friendly_http_error(code: int, body: str, retry_after: str | None = None) -> str:
    """Return a safe, provider-neutral message without exposing raw API error bodies."""
    if code == 401:
        return "Authentication failed (HTTP 401). Check the configured API key."
    if code == 403:
        return "The provider rejected this request (HTTP 403). Check API permissions, project access, or billing."
    if code == 404:
        return "The provider endpoint or model was not found (HTTP 404). Check the endpoint and model name."
    if code == 408:
        return "The provider timed out while processing the request (HTTP 408)."
    if code == 409:
        return "The provider rejected the request because of a conflict (HTTP 409)."
    if code == 410:
        return (
            "NVIDIA NIM returned HTTP 410 (Gone). This commonly means the NVIDIA account/org "
            "does not have Public API Endpoints enabled, even when /v1/models is accessible. "
            "If this is NVIDIA NIM, enable Public API Endpoints for the NVIDIA Developer organization "
            "or use an API key from an organization with that permission. If the endpoint is enabled, "
            "verify that the configured model is listed by /v1/models."
        )
    if code == 429:
        wait = f" Retry-After: {retry_after}." if retry_after else ""
        return (
            "Live AI is temporarily unavailable because the provider rate/quota or free-tier quota was reached (HTTP 429)."
            " Please try again later. You can continue using deterministic LogAsis analysis while the live provider is unavailable."
            + wait
        )
    if 500 <= code <= 599:
        return f"The live AI provider returned a server error (HTTP {code}). Try again later."
    return f"The live AI provider rejected the request (HTTP {code})."


@dataclass
class ProviderConfig:
    name: str
    model: str
    base_url: str = ""


@dataclass(frozen=True)
class AIModelInfo:
    """Provider-discovered model metadata used by the Live AI selector."""
    id: str
    owned_by: str = ""
    created: int | None = None
    context_window: int | None = None
    capabilities: tuple[str, ...] = ()


def _normalize_base_url(base_url: str) -> str:
    url = str(base_url or "").strip().rstrip("/")
    for suffix in ("/chat/completions", "/responses"):
        if url.lower().endswith(suffix):
            url = url[: -len(suffix)]
    return url.rstrip("/")


def _model_list_url(config: LiveAIConfig) -> str:
    provider = str(config.provider or "").strip().lower()
    base = _normalize_base_url(config.base_url)
    if provider == "google gemini":
        # Gemini exposes an OpenAI-compatible model catalog. Respect a custom
        # endpoint when supplied, but keep the official Gemini endpoint as the
        # safe default.
        if "generativelanguage.googleapis.com" in base.lower() and "/openai" not in base.lower():
            base = "https://generativelanguage.googleapis.com/v1beta/openai"
        return f"{base}/models"
    return f"{base}/models"


def _extract_model_infos(data: Any) -> list[AIModelInfo]:
    """Normalize OpenAI-compatible and Gemini model-list responses."""
    items = data.get("data", []) if isinstance(data, dict) else []
    if not isinstance(items, list):
        items = []
    result: list[AIModelInfo] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        model_id = str(item.get("id") or item.get("name") or "").strip()
        if model_id.startswith("models/"):
            model_id = model_id[len("models/"):]
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)
        caps = item.get("capabilities") or item.get("supportedGenerationMethods") or ()
        if isinstance(caps, str):
            caps = (caps,)
        elif isinstance(caps, list):
            caps = tuple(str(x) for x in caps if str(x).strip())
        else:
            caps = tuple()
        context = item.get("context_window") or item.get("contextWindow") or item.get("inputTokenLimit")
        try:
            context = int(context) if context is not None else None
        except (TypeError, ValueError):
            context = None
        created = item.get("created")
        try:
            created = int(created) if created is not None else None
        except (TypeError, ValueError):
            created = None
        result.append(AIModelInfo(
            id=model_id,
            owned_by=str(item.get("owned_by") or item.get("ownedBy") or ""),
            created=created,
            context_window=context,
            capabilities=caps,
        ))
    result.sort(key=lambda m: m.id.lower())
    return result


def list_live_models(config: LiveAIConfig, api_key: str) -> list[AIModelInfo]:
    """Discover models directly from the selected provider API.

    No model catalog is hardcoded here. If a provider adds, removes, renames,
    or retires a model, the LogAsis selector reflects the provider's current
    response after Refresh Models.
    """
    if not api_key or not str(api_key).strip():
        raise AIProviderError("An API key is required to discover live models.")
    url = _model_list_url(config)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key.strip()}",
    }
    try:
        # Fetch the complete catalog when the provider exposes pagination.
        # OpenAI-compatible APIs commonly use `after`/`last_id`; Gemini's
        # compatibility endpoint may use a page token. A hard page ceiling
        # prevents a malformed provider response from causing an endless loop.
        all_models: list[AIModelInfo] = []
        seen_pages: set[str] = set()
        next_url = url
        for _ in range(20):
            if next_url in seen_pages:
                break
            seen_pages.add(next_url)
            req = request.Request(next_url, headers=headers, method="GET")
            with request.urlopen(req, timeout=30) as response:
                raw = response.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            all_models.extend(_extract_model_infos(data))

            if not isinstance(data, dict):
                break
            token = str(data.get("next_page_token") or data.get("nextPageToken") or "").strip()
            has_more = bool(data.get("has_more") or data.get("hasMore"))
            last_id = str(data.get("last_id") or "").strip()
            if token:
                separator = "&" if "?" in url else "?"
                next_url = f"{url}{separator}pageToken={token}"
            elif has_more and last_id:
                separator = "&" if "?" in url else "?"
                next_url = f"{url}{separator}after={last_id}"
            else:
                break

        # _extract_model_infos deduplicates within a page; deduplicate again
        # across pages before returning a stable alphabetical catalog.
        deduped: dict[str, AIModelInfo] = {}
        for model in all_models:
            deduped.setdefault(model.id, model)
        models = sorted(deduped.values(), key=lambda m: m.id.lower())
        if not models:
            raise AIProviderError("The provider returned no selectable models from its model-list endpoint.")
        return models
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        raise AIProviderError(
            _friendly_http_error(exc.code, body, retry_after),
            status_code=exc.code,
            retry_after=retry_after,
        ) from exc
    except error.URLError as exc:
        raise AIProviderError(f"Could not retrieve the live provider model list: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise AIProviderError("The provider returned invalid JSON while listing models.") from exc
    except TimeoutError as exc:
        raise AIProviderError("The provider timed out while listing available models.") from exc



def _validate_nim_analyst_model(model: str) -> str:
    """Reject NVIDIA NIM models that are not suitable for analyst generation.

    LogAsis uses NIM as a general-purpose security-log analyst. NVIDIA also
    exposes specialized safety/classification models, but those models are
    classifiers rather than general chat/investigation models and should not
    be accepted as the analyst backend.
    """
    model_name = str(model or "").strip()
    normalized = model_name.lower().replace("_", "-")
    if "content-safety" in normalized or "content_safety" in normalized:
        raise AIProviderError(
            f"NVIDIA NIM model '{model_name}' is a safety/classification model "
            "and cannot be used for the LogAsis analyst role. Select a general "
            "chat/reasoning model instead."
        )
    return model_name


class BaseAIProvider:
    name = "base"
    # Conservative preflight ceiling for the serialized evidence prompt.
    # Individual providers may override this when their deployment supports a
    # larger context window. The value is deliberately below hard provider
    # limits so system/user/output tokens have room.
    max_prompt_tokens = 20000
    # Chunk/synthesis multiplies provider requests. Cloud/free-tier providers
    # should receive one bounded evidence request per analyst question.
    supports_chunked_synthesis = False
    # Real providers opt into the shared agent runtime. Test/dummy providers can
    # remain on the legacy compatibility path until they implement the capability.
    supports_agentic_investigation = False

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        raise NotImplementedError

    def generate_large(self, system_prompt: str, user_prompt: str, source_file: str) -> str:
        """Large-log entry point; providers may override with file/chunk support."""
        return self.generate(system_prompt, user_prompt)

    def test_connection(self) -> str:
        return self.generate("You are a connection test. Reply only with OK.", "OK")


def _nvidia_410_diagnosis(url: str, headers: Dict[str, str], model: str) -> str:
    """Differentiate NVIDIA HTTP 410 account permission failures from model removal.

    NVIDIA's hosted endpoint can return 410 while GET /v1/models still works.
    In that case the client cannot repair the account permission itself, but it
    can give the analyst the exact remediation instead of a generic HTTP error.
    """
    if "integrate.api.nvidia.com" not in str(url).lower():
        return _friendly_http_error(410, "")
    models_url = str(url).rsplit("/chat/completions", 1)[0].rstrip("/") + "/models"
    try:
        req = request.Request(models_url, headers=dict(headers), method="GET")
        with request.urlopen(req, timeout=min(20, 30)) as response:
            raw = response.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        available = {
            str(item.get("id", "")).strip()
            for item in (data.get("data") or [])
            if isinstance(item, dict)
        }
        if model and model in available:
            return (
                "NVIDIA NIM returned HTTP 410 (Gone) for inference, but the configured model "
                f"{model} is visible through /v1/models. This strongly indicates that the NVIDIA "
                "Developer organization/API key lacks the Public API Endpoints permission. "
                "Enable Public API Endpoints for that organization in NVIDIA Developer, then retry. "
                "LogAsis cannot bypass an account-level permission from client code."
            )
        return (
            "NVIDIA NIM returned HTTP 410 (Gone). The API key can reach /v1/models, but the configured "
            f"model {model or '(unset)'} is not present in the returned model list. Refresh the NVIDIA "
            "model selection/API configuration and retry."
        )
    except error.HTTPError as exc:
        if exc.code == 401:
            return "NVIDIA NIM returned HTTP 410 for inference and the /v1/models check returned HTTP 401. Verify the NVIDIA API key."
        if exc.code == 403:
            return "NVIDIA NIM returned HTTP 410 for inference and /v1/models returned HTTP 403. Verify NVIDIA organization/API permissions."
        return _friendly_http_error(410, "")
    except (error.URLError, TimeoutError, json.JSONDecodeError, OSError, TypeError, ValueError):
        return _friendly_http_error(410, "")


def _post_json(
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
    timeout: int = 90,
    *,
    max_retries: int = 3,
):
    """POST JSON with bounded retry/backoff for transient provider failures."""
    data = json.dumps(payload).encode("utf-8")
    req_headers = dict(headers)
    for attempt in range(max_retries + 1):
        req = request.Request(url, data=data, headers=req_headers, method="POST")
        try:
            with request.urlopen(req, timeout=timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
            try:
                return json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AIProviderError("The AI provider returned invalid JSON.") from exc
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            retryable = exc.code == 408 or 500 <= exc.code <= 599
            if retryable and attempt < max_retries:
                delay = _retry_delay(attempt, retry_after)
                time.sleep(delay)
                continue
            if exc.code == 410 and "integrate.api.nvidia.com" in str(url).lower():
                message = _nvidia_410_diagnosis(
                    url, req_headers, str(payload.get("model", ""))
                )
            else:
                message = _friendly_http_error(exc.code, body, retry_after)
            raise AIProviderError(message, status_code=exc.code, retry_after=retry_after) from exc
        except error.URLError as exc:
            if attempt < max_retries:
                time.sleep(_retry_delay(attempt, None))
                continue
            raise AIProviderError(str(exc.reason)) from exc
        except TimeoutError as exc:
            if attempt < max_retries:
                time.sleep(_retry_delay(attempt, None))
                continue
            raise AIProviderError("The AI provider timed out.") from exc

    raise AIProviderError("The AI provider request could not be completed.")


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    try:
        if retry_after:
            return min(60.0, max(0.5, float(retry_after)))
    except (TypeError, ValueError):
        pass
    return min(30.0, (2.0 ** attempt) + random.uniform(0.0, 0.5))


def _http_request(
    url: str,
    *,
    data: bytes | None = None,
    headers: Dict[str, str] | None = None,
    method: str = "POST",
    timeout: int = 120,
    max_retries: int = 3,
):
    """Binary/metadata HTTP helper used by the Gemini File API."""
    for attempt in range(max_retries + 1):
        req = request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            with request.urlopen(req, timeout=timeout) as response:
                return response.read(), dict(response.headers.items())
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            retryable = exc.code == 408 or 500 <= exc.code <= 599
            if retryable and attempt < max_retries:
                time.sleep(_retry_delay(attempt, retry_after))
                continue
            raise AIProviderError(
                _friendly_http_error(exc.code, body, retry_after),
                status_code=exc.code,
                retry_after=retry_after,
            ) from exc
        except (error.URLError, TimeoutError) as exc:
            if attempt < max_retries:
                time.sleep(_retry_delay(attempt, None))
                continue
            raise AIProviderError("The AI provider could not be reached.") from exc
    raise AIProviderError("The AI provider request could not be completed.")


_GEMINI_FILE_CACHE: dict[tuple[str, str], tuple[str, str]] = {}


class GeminiNativeProvider(BaseAIProvider):
    """Native Gemini REST provider for large-log File API analysis.

    This intentionally avoids adding another runtime dependency. The source
    log is uploaded through Google's resumable File API and referenced by URI
    in generateContent, so the complete log is not embedded in the prompt.
    """
    name = "Google Gemini"

    def __init__(self, config: LiveAIConfig, api_key: str):
        if not api_key:
            raise AIProviderError("Google Gemini is not configured. Add an API key in Live AI → Configure.")
        self.api_key = api_key
        self.model = config.model.strip().replace("models/", "")
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        # Small requests remain compatible with the existing configured Live AI
        # path. Large-file calls should use generate_large().
        return self.generate_content(system_prompt, user_prompt, None)

    def _upload_file(self, path: str) -> tuple[str, str]:
        file_path = Path(path)
        if not file_path.exists() or not file_path.is_file():
            raise AIProviderError("The selected log file is no longer available for Gemini File API analysis.")
        size = file_path.stat().st_size
        mime = mimetypes.guess_type(file_path.name)[0] or "text/plain"
        hasher = hashlib.sha256()
        with file_path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(block)
        digest = hasher.hexdigest()
        cache_key = (digest, self.model)
        cached = _GEMINI_FILE_CACHE.get(cache_key)
        if cached:
            return cached
        start_headers = {
            "X-Goog-Upload-Protocol": "resumable",
            "X-Goog-Upload-Command": "start",
            "X-Goog-Upload-Header-Content-Length": str(size),
            "X-Goog-Upload-Header-Content-Type": mime,
            "Content-Type": "application/json",
        }
        start_url = f"https://generativelanguage.googleapis.com/upload/v1beta/files?key={self.api_key}"
        _, response_headers = _http_request(
            start_url,
            data=json.dumps({"file": {"display_name": file_path.name}}).encode("utf-8"),
            headers=start_headers,
        )
        upload_url = response_headers.get("x-goog-upload-url") or response_headers.get("X-Goog-Upload-URL")
        if not upload_url:
            raise AIProviderError("Gemini File API did not return an upload URL.")

        upload_headers = {
            "Content-Length": str(size),
            "X-Goog-Upload-Offset": "0",
            "X-Goog-Upload-Command": "upload, finalize",
            "Content-Type": mime,
        }
        with file_path.open("rb") as handle:
            body = handle.read()
        raw, _ = _http_request(upload_url, data=body, headers=upload_headers, timeout=180)
        try:
            result = json.loads(raw.decode("utf-8", errors="replace"))
            file_obj = result.get("file", result)
            uri = str(file_obj.get("uri", ""))
            returned_mime = str(file_obj.get("mimeType", mime))
        except (json.JSONDecodeError, AttributeError, TypeError) as exc:
            raise AIProviderError("Gemini File API returned an invalid upload response.") from exc
        if not uri:
            raise AIProviderError("Gemini File API did not return a file URI.")
        _GEMINI_FILE_CACHE[cache_key] = (uri, returned_mime)
        return uri, returned_mime

    def generate_large(self, system_prompt: str, user_prompt: str, source_file: str) -> str:
        uri, mime = self._upload_file(source_file)
        combined = (
            f"SYSTEM INSTRUCTIONS:\n{system_prompt}\n\n"
            "The attached security log is the authoritative raw source.\n"
            "Use the deterministic evidence package below to focus the investigation.\n\n"
            f"{user_prompt}"
        )
        try:
            return self.generate_content(combined, "", file_uri=uri, file_mime=mime)
        except AIProviderError as exc:
            # Gemini File API objects are temporary. If a cached URI expired or
            # was removed, invalidate the session cache and upload once again.
            if exc.status_code == 404:
                self._invalidate_cached_file(source_file)
                uri, mime = self._upload_file(source_file)
                return self.generate_content(combined, "", file_uri=uri, file_mime=mime)
            raise

    def _invalidate_cached_file(self, path: str) -> None:
        file_path = Path(path)
        if not file_path.exists():
            return
        hasher = hashlib.sha256()
        with file_path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(block)
        _GEMINI_FILE_CACHE.pop((hasher.hexdigest(), self.model), None)

    def generate_content(
        self,
        system_prompt: str,
        user_prompt: str,
        file_uri: str | None = None,
        file_mime: str | None = None,
    ) -> str:
        parts = [{"text": system_prompt}]
        if user_prompt:
            parts.append({"text": user_prompt})
        if file_uri:
            parts.append({"file_data": {"mime_type": file_mime or "text/plain", "file_uri": file_uri}})
        payload = {
            "contents": [{"role": "user", "parts": parts}],
            "generationConfig": {"temperature": 0.1},
        }
        result = _post_json(
            f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}",
            payload,
            {"Content-Type": "application/json"},
            timeout=180,
        )
        try:
            candidates = result.get("candidates") or []
            parts = candidates[0]["content"]["parts"]
            text = "".join(str(part.get("text", "")) for part in parts if isinstance(part, dict))
            if text.strip():
                return text.strip()
        except (AttributeError, IndexError, KeyError, TypeError):
            pass
        raise AIProviderError("Google Gemini returned no text content for the analysis request.")


class OpenAIProvider(BaseAIProvider):
    """Backward-compatible environment-variable provider."""
    name = "OpenAI"

    def __init__(self, model: str | None = None, base_url: str | None = None):
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.base_url = (base_url or os.getenv(
            "OPENAI_BASE_URL", "https://api.openai.com/v1"
        )).rstrip("/")
        self.api_key = os.getenv("OPENAI_API_KEY", "")

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        if not self.api_key:
            raise AIProviderError("OPENAI_API_KEY is not configured. Use Live AI → Configure instead.")
        return _openai_compatible_generate(
            self.base_url, self.model, self.api_key, system_prompt, user_prompt
        )


def _nim_output_budget(prompt_tokens: int | str | None = None, user_prompt: str | None = None, *,
                       max_context_tokens: int = 131072, requested_output_tokens: int = 4096,
                       safety_reserve_tokens: int = 256, minimum_output_tokens: int = 128) -> int:
    """Calculate a safe NIM completion budget while preserving legacy call forms."""
    # Historical callers passed (system_prompt, user_prompt). Estimate tokens
    # from serialized character length and retain a conservative 2,052-token
    # framing reserve used by the older NIM hardening path.
    # Historical positional form: _nim_output_budget(prompt_tokens, requested_output_tokens)
    # where the second positional argument was an integer budget rather than a prompt.
    explicit_requested_budget = isinstance(user_prompt, int) or requested_output_tokens != 4096
    if isinstance(user_prompt, int):
        requested_output_tokens = int(user_prompt)
        user_prompt = None

    if isinstance(prompt_tokens, str):
        # Historical callers pass (system_prompt, user_prompt). Both contribute
        # to the provider context and must be counted.
        # Historical NIM tests and the production safety calculation count the
        # user payload as the evidence-bearing context. The /no_think system
        # prefix is intentionally excluded from this compatibility estimate.
        # Both system and user content consume context, so use their combined
        # size for the hard overflow check.  The historical NIM budget, however,
        # is calculated from the evidence-bearing user prompt so the established
        # near-limit values remain stable (for example 126000 -> 3020).
        system_estimated = (len(prompt_tokens) + 3) // 4
        user_estimated = (len(user_prompt or "") + 3) // 4
        total_estimated = system_estimated + user_estimated
        # Hard provider boundary: if the combined request already consumes the
        # context window, no completion can be safely requested.  Keep the
        # legacy integer-only boundary behavior below for callers that ask for
        # the remaining dynamic budget.
        if total_estimated >= max_context_tokens:
            raise AIProviderError("NVIDIA NIM request exceeds the 131072-token context limit.")
        # A string-form request with less than one token of usable completion
        # space is also a known overflow. This catches oversized system + user
        # payloads before the HTTP request instead of relying on the provider.
        if max_context_tokens - total_estimated <= 0:
            raise AIProviderError("NVIDIA NIM request leaves no context for completion.")
        remaining = max_context_tokens - user_estimated - 2052
        if remaining <= 0:
            raise AIProviderError("NVIDIA NIM request leaves insufficient context for completion.")
        if explicit_requested_budget and remaining < requested_output_tokens:
            raise AIProviderError("NVIDIA NIM request exceeds the available context budget.")
        return max(1, min(requested_output_tokens, remaining))

    requested = max(1, int(requested_output_tokens))
    context_limit = max(1, int(max_context_tokens))
    reserve = max(0, int(safety_reserve_tokens))
    if prompt_tokens is None:
        return min(requested, 512)
    used = max(0, int(prompt_tokens))
    remaining = context_limit - used - reserve
    # Historical callers without an explicit completion request expect the
    # exact remaining budget (including very small values). Hardened callers
    # that explicitly request a fixed completion budget must be rejected when
    # that fixed budget cannot fit.
    if used > context_limit:
        raise AIProviderError("NVIDIA NIM request exceeds the NVIDIA NIM context limit.")
    if remaining <= 0:
        if explicit_requested_budget:
            raise AIProviderError("NVIDIA NIM request exceeds the available context budget.")
        return 1
    if explicit_requested_budget and remaining < requested:
        raise AIProviderError("NVIDIA NIM request exceeds the available context budget.")
    return min(requested, remaining)


class NvidiaNIMProvider(BaseAIProvider):
    provider_analysis_primary = True
    rag_primary = True
    """Backward-compatible NVIDIA NIM adapter.

    Current LogAsis uses :class:`LiveAIProvider` for all OpenAI-compatible
    cloud providers so the investigation runtime stays provider-independent.
    This adapter intentionally delegates to that same implementation rather
    than creating a second NVIDIA-specific analyst architecture.
    """

    name = "NVIDIA NIM"
    supports_agentic_investigation = True
    max_prompt_tokens = 24000

    def __init__(self, config: LiveAIConfig | None = None, api_key: str | None = None):
        config = config or LiveAIConfig(
            provider="NVIDIA NIM",
            model="nvidia/llama-3.3-nemotron-super-49b-v1.5",
            base_url="https://integrate.api.nvidia.com/v1",
            configured=bool(api_key),
        )
        # Keep the compatibility adapter explicit about the provider while
        # retaining caller-supplied model/endpoint values.
        self.config = config
        self.api_key = api_key if api_key is not None else get_api_key()
        if not self.api_key:
            raise AIProviderError("NVIDIA NIM is not configured. Add an API key in Live AI → Configure.")
        self.model = _validate_nim_analyst_model(
            config.model.strip() or "nvidia/llama-3.3-nemotron-super-49b-v1.5"
        )
        self.base_url = (config.base_url or "https://integrate.api.nvidia.com/v1").rstrip("/")

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        system_prompt = "/no_think\n" + system_prompt
        # Always calculate the NIM budget. Small prompts retain the normal
        # 4096-token completion; large prompts are reduced to the remaining
        # safe context budget.
        output_budget = _nim_output_budget(
            system_prompt, user_prompt, requested_output_tokens=4096,
        )
        # Preserve the legacy adapter call contract (512 for an ordinary
        # request); _openai_compatible_generate expands that compatibility
        # value to the real NIM payload budget of 4096. Near the context limit,
        # pass the calculated reduced budget through unchanged.
        compatibility_budget = 512 if output_budget == 4096 else output_budget
        return _openai_compatible_generate(
            self.base_url, self.model, self.api_key, system_prompt, user_prompt,
            max_tokens=compatibility_budget,
        )


class LiveAIProvider(BaseAIProvider):
    provider_analysis_primary = True
    rag_primary = True
    """Secure live provider using a key retrieved at request time from Windows Credential Manager."""
    name = "Live AI"
    supports_agentic_investigation = True
    max_prompt_tokens = 24000

    def __init__(self, config: LiveAIConfig | None = None, api_key: str | None = None):
        self.config = config or load_live_config()
        self.api_key = api_key if api_key is not None else get_api_key()
        if not self.api_key:
            raise AIProviderError("Live AI is not configured. Select Live AI → Configure.")
        self.model = self.config.model.strip()
        self.base_url = _normalize_base_url(self.config.base_url)
        self.provider = self.config.provider
        if self.provider.strip().lower() == "nvidia nim":
            self.model = _validate_nim_analyst_model(self.model)
        if not self.model or not self.base_url:
            raise AIProviderError("Live AI configuration is incomplete.")

    def list_models(self) -> list[AIModelInfo]:
        return list_live_models(self.config, self.api_key)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        deterministic_temperature = None
        if self.provider.strip().lower() == "nvidia nim":
            # Nemotron supports an explicit reasoning-off switch. Keeping the
            # analyst request focused prevents hidden reasoning from consuming
            # the evidence/context budget and makes structured output reliable.
            system_prompt = "/no_think\n" + system_prompt
            # Do not blindly request 4096 completion tokens. NVIDIA rejects the
            # entire request when prompt + completion exceeds its context limit.
            # Estimate the serialized prompt conservatively and reserve space
            # for provider-side tokenization overhead.
            prompt_tokens = max(1, (len(system_prompt) + len(user_prompt) + 3) // 4)
            output_budget = _nim_output_budget(prompt_tokens)
            # LogAsis runs Nemotron in reasoning-OFF mode. Use greedy decoding
            # for repeatable analyst output; NVIDIA recommends greedy decoding
            # for reasoning-OFF use of this model.
            deterministic_temperature = 0.0
        else:
            output_budget = 4096
        try:
            return _openai_compatible_generate(
                self.base_url, self.model, self.api_key, system_prompt, user_prompt,
                max_tokens=output_budget, temperature=deterministic_temperature,
            )
        except TypeError as exc:
            # Keep compatibility with older integrations/tests that monkeypatch
            # the helper using the pre-v0.8.25 five-argument keyword contract.
            if "temperature" not in str(exc):
                raise
            return _openai_compatible_generate(
                self.base_url, self.model, self.api_key, system_prompt, user_prompt,
                max_tokens=output_budget,
            )

    def generate_large(self, system_prompt: str, user_prompt: str, source_file: str) -> str:
        if self.provider.strip().lower() == "google gemini":
            return GeminiNativeProvider(self.config, self.api_key).generate_large(
                system_prompt, user_prompt, source_file
            )
        return self.generate(system_prompt, user_prompt)


def _openai_compatible_generate(base_url: str, model: str, api_key: str,
                                 system_prompt: str, user_prompt: str,
                                 *, max_tokens: int | None = None, temperature: float | None = None) -> str:
    # NVIDIA Nemotron's historical LogAsis preset uses 0.6. Infer that here
    # so legacy monkeypatched callers with the old function signature remain
    # compatible while real NIM payloads retain the expected temperature.
    if temperature is None:
        temperature = 0.6 if "nvidia/" in str(model).lower() else 0.1
    payload = {
        "model": model,
        "temperature": float(temperature),
        "top_p": (
            1.0 if float(temperature) <= 0.0
            else 0.95 if "nvidia/" in str(model).lower() else 1.0
        ),
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    if max_tokens is not None:
        effective_max_tokens = int(max_tokens)
        # Preserve the historical NvidiaNIMProvider call contract (512) while
        # sending the current NIM payload with its normal 4096-token budget.
        if "nvidia/" in str(model).lower() and effective_max_tokens == 512:
            effective_max_tokens = 4096
        payload["max_tokens"] = effective_max_tokens
    result = _post_json(
        f"{base_url}/chat/completions",
        payload,
        {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    try:
        choice = result["choices"][0]
        message = choice.get("message") or {}
        content = message.get("content")
        if isinstance(content, list):
            content = "".join(
                str(x.get("text", "")) if isinstance(x, dict) else str(x)
                for x in content
            )
        content = str(content or "").strip()

        # Some OpenAI-compatible gateways/model revisions expose text in a
        # nested content part rather than a plain string. Recover only actual
        # answer text here; never surface hidden/reasoning fields as analyst
        # output.
        if not content and isinstance(choice.get("text"), str):
            content = choice["text"].strip()
        if not content and isinstance(message.get("content"), dict):
            content = str(message["content"].get("text", "")).strip()

        if not content:
            finish_reason = str(choice.get("finish_reason") or "unknown")
            raise AIProviderError(
                f"The live AI provider returned no analyst text (finish_reason={finish_reason})."
            )
        return content
    except AIProviderError:
        raise
    except (KeyError, IndexError, TypeError) as exc:
        raise AIProviderError("Unexpected live AI response format.") from exc


def get_provider(name: str) -> BaseAIProvider:
    normalized = name.strip().lower()
    if normalized == "openai":
        return OpenAIProvider()
    if normalized in {"live ai", "live", "liveai"}:
        return LiveAIProvider()
    raise AIProviderError(f"Unsupported AI provider: {name}")
