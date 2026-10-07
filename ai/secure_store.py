from __future__ import annotations

import ctypes
from ctypes import wintypes


class SecureStoreError(RuntimeError):
    pass


_CREDENTIAL_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2


if hasattr(ctypes, "windll"):
    class _CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", ctypes.c_byte * 8),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]


def _require_windows() -> None:
    if not hasattr(ctypes, "windll"):
        raise SecureStoreError("Windows Credential Manager is only available on Windows.")


def write_secret(target: str, secret: str) -> None:
    """Store a UTF-8 secret in Windows Credential Manager, never in project files."""
    _require_windows()
    if not secret:
        raise SecureStoreError("Cannot store an empty secret.")

    blob = secret.encode("utf-8")
    blob_buffer = ctypes.create_string_buffer(blob)
    credential = _CREDENTIAL()
    credential.Type = _CREDENTIAL_TYPE_GENERIC
    credential.TargetName = target
    credential.CredentialBlobSize = len(blob)
    credential.CredentialBlob = ctypes.cast(blob_buffer, ctypes.POINTER(ctypes.c_ubyte))
    credential.Persist = _CRED_PERSIST_LOCAL_MACHINE
    credential.UserName = "LogAsis"

    if not ctypes.windll.advapi32.CredWriteW(ctypes.byref(credential), 0):
        raise ctypes.WinError()


def read_secret(target: str) -> str | None:
    _require_windows()
    credential_ptr = ctypes.POINTER(_CREDENTIAL)()
    if not ctypes.windll.advapi32.CredReadW(
        target, _CREDENTIAL_TYPE_GENERIC, 0, ctypes.byref(credential_ptr)
    ):
        error_code = ctypes.GetLastError()
        # ERROR_NOT_FOUND
        if error_code == 1168:
            return None
        raise ctypes.WinError(error_code)

    try:
        credential = credential_ptr.contents
        if not credential.CredentialBlob or not credential.CredentialBlobSize:
            return None
        raw = ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize)
        return raw.decode("utf-8")
    finally:
        ctypes.windll.advapi32.CredFree(credential_ptr)


def delete_secret(target: str) -> None:
    _require_windows()
    if not ctypes.windll.advapi32.CredDeleteW(target, _CREDENTIAL_TYPE_GENERIC, 0):
        error_code = ctypes.GetLastError()
        if error_code != 1168:
            raise ctypes.WinError(error_code)
