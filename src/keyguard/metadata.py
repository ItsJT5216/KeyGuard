from __future__ import annotations

import itertools
import re
from typing import Any

_SECRET_FIELDS = frozenset(
    {
        "accesskey",
        "accesstoken",
        "apikey",
        "apisecret",
        "authorization",
        "authtoken",
        "bearertoken",
        "clientsecret",
        "credential",
        "credentials",
        "managementkey",
        "passphrase",
        "password",
        "privatekey",
        "secret",
        "secretkey",
        "token",
    }
)
_SECRET_COMPONENTS = frozenset(
    {"authorization", "bearer", "password", "passphrase", "secret", "token"}
)
_SECRET_PAIRS = frozenset(
    {
        ("access", "key"),
        ("api", "key"),
        ("api", "secret"),
        ("client", "secret"),
        ("management", "key"),
        ("pass", "phrase"),
        ("private", "key"),
        ("secret", "key"),
    }
)
_SAFE_SUFFIXES = frozenset(
    {"fingerprint", "hash", "hint", "id", "identifier", "last4", "prefix", "suffix"}
)


def is_secret_metadata_field(key: str) -> bool:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    components = tuple(
        component.casefold()
        for component in re.split(r"[^0-9A-Za-z]+", separated)
        if component
    )
    if not components:
        return False
    if components[-1] in _SAFE_SUFFIXES:
        return False
    if any(component in _SECRET_COMPONENTS for component in components):
        return True
    if any(pair in _SECRET_PAIRS for pair in itertools.pairwise(components)):
        return True
    normalized = "".join(character for character in key.casefold() if character.isalnum())
    return any(normalized.endswith(field) for field in _SECRET_FIELDS)


def contains_secret_metadata_field(value: Any) -> bool:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            for key, nested in current.items():
                if not isinstance(key, str):
                    raise TypeError("metadata keys must be text")
                if is_secret_metadata_field(key):
                    return True
                pending.append(nested)
        elif isinstance(current, list):
            pending.extend(current)
    return False


def scrub_secret_metadata_fields(value: Any) -> tuple[Any, bool]:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        changed = False
        for key, nested in value.items():
            if not isinstance(key, str) or is_secret_metadata_field(key):
                changed = True
                continue
            cleaned_value, nested_changed = scrub_secret_metadata_fields(nested)
            cleaned[key] = cleaned_value
            changed = changed or nested_changed
        return cleaned, changed
    if isinstance(value, list):
        cleaned_list = []
        changed = False
        for nested in value:
            cleaned_value, nested_changed = scrub_secret_metadata_fields(nested)
            cleaned_list.append(cleaned_value)
            changed = changed or nested_changed
        return cleaned_list, changed
    return value, False
