"""Shared session state for target/scope configuration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse


@dataclass
class ScopeRule:
    raw: str
    host: str
    path: str
    wildcard: bool

    def matches(self, host: str, path: str) -> bool:
        if not host:
            return False
        if self.wildcard:
            if not host.endswith(self.host) and host != self.host.lstrip('.'):
                return False
        elif host != self.host:
            return False
        if self.path and not path.startswith(self.path):
            return False
        return True


class _SessionState:
    def __init__(self) -> None:
        self._target: str = ''
        self._scope: List[ScopeRule] = []

    # target helpers
    def get_target(self) -> str:
        return self._target

    def set_target(self, value: str) -> None:
        self._target = value.strip()

    # scope helpers
    def set_scope_from_text(self, text: str) -> None:
        rules: List[ScopeRule] = []
        for line in text.splitlines():
            entry = line.strip().lower()
            if not entry:
                continue
            wildcard = False
            host = ''
            path = ''
            if entry.startswith('http://') or entry.startswith('https://'):
                parsed = urlparse(entry)
                host = parsed.netloc.lower()
                path = parsed.path.rstrip('/') or '/'
            else:
                if entry.startswith('*.'):
                    wildcard = True
                    entry = entry[2:]
                parts = entry.split('/', 1)
                host = parts[0].lower()
                if len(parts) == 2:
                    path = '/' + parts[1]
            host = host.lstrip('.').strip()
            if not host:
                continue
            rules.append(ScopeRule(raw=line.strip(), host=host, path=path, wildcard=wildcard))
        self._scope = rules

    def get_scope_text(self) -> str:
        if not self._scope:
            return ''
        return '\n'.join(rule.raw for rule in self._scope)

    def describe_scope(self) -> str:
        if not self._scope:
            return 'Scope is open (no restrictions).'
        return f"Scope restricted to {len(self._scope)} rule(s)."

    def is_url_in_scope(self, url: str) -> bool:
        if not self._scope:
            return True
        if not url:
            return False
        if '://' not in url:
            url = f'http://{url}'
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        path = parsed.path or '/'
        for rule in self._scope:
            if rule.matches(host, path):
                return True
        return False

    def scope_error(self, url: str) -> str:
        return ("The target appears to be outside of the configured scope.\n"
                "Update the scope in the main window or clear the scope to scan this host.")


session_state = _SessionState()

# convenience accessors
get_target = session_state.get_target
set_target = session_state.set_target
set_scope_from_text = session_state.set_scope_from_text
get_scope_text = session_state.get_scope_text
is_url_in_scope = session_state.is_url_in_scope
scope_error = session_state.scope_error
describe_scope = session_state.describe_scope
