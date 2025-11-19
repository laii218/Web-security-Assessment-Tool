"""HTTP fingerprinting helpers for version/technology detection."""
from __future__ import annotations

import json
import re
import socket
import ssl
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional
from urllib.parse import urljoin, urlparse

import requests

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
)
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)",
    re.IGNORECASE,
)
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
WORDPRESS_RE = re.compile(r"wp-content|wp-includes", re.IGNORECASE)
DRUPAL_RE = re.compile(r"/sites/default/", re.IGNORECASE)
JOOMLA_RE = re.compile(r"/media/system/js/|/templates/", re.IGNORECASE)
REACT_RE = re.compile(r"react", re.IGNORECASE)
ANGULAR_RE = re.compile(r"angular", re.IGNORECASE)
VUE_RE = re.compile(r"vue", re.IGNORECASE)
DJANGO_RE = re.compile(r"csrftoken", re.IGNORECASE)
LARAVEL_RE = re.compile(r"laravel|x-csrf-token", re.IGNORECASE)

INTERESTING_PATHS = [
    ("/robots.txt", "Robots file"),
    ("/sitemap.xml", "Sitemap"),
    ("/server-status?auto", "Apache server-status"),
    ("/.git/HEAD", "Git metadata"),
    ("/wp-login.php", "WordPress login"),
    ("/actuator/health", "Spring Boot actuator"),
]


@dataclass
class Fingerprint:
    url: str
    status: Optional[int]
    headers: Dict[str, str]
    technologies: List[str]
    versions: List[str]
    missing_headers: List[str]
    title: str
    interesting: List[str]
    certificate: Optional[str]
    error: Optional[str] = None

    def to_report(self) -> str:
        if self.error:
            return f"[!] {self.url}\n    Error: {self.error}\n"
        lines = [f"[*] {self.url}"]
        if self.status is not None:
            lines.append(f"    Status: {self.status}")
        if self.title:
            lines.append(f"    Title: {self.title.strip()}")
        if self.technologies:
            lines.append(f"    Technologies: {', '.join(sorted(self.technologies))}")
        if self.versions:
            lines.append(f"    Version Clues: {', '.join(self.versions)}")
        if self.certificate:
            lines.append(f"    Certificate: {self.certificate}")
        if self.headers:
            server = self.headers.get("Server")
            powered = self.headers.get("X-Powered-By")
            if server:
                lines.append(f"    Server: {server}")
            if powered:
                lines.append(f"    X-Powered-By: {powered}")
        if self.missing_headers:
            lines.append(
                "    Missing Security Headers: "
                + ", ".join(self.missing_headers)
            )
        if self.interesting:
            lines.append("    Interesting: " + "; ".join(self.interesting))
        return "\n".join(lines) + "\n"


def _clean_url(url: str) -> str:
    if not url:
        return url
    if not url.startswith("http://") and not url.startswith("https://"):
        return "http://" + url
    return url


def _get_certificate_description(parsed):
    if parsed.scheme != "https":
        return None
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return None
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except OSError:
        return None
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    cn = subject.get("commonName", "?")
    issuer_cn = issuer.get("commonName", "?")
    not_after = cert.get("notAfter", "?")
    return f"CN={cn} | Issuer={issuer_cn} | Expires={not_after}"


def _extract_versions(headers: Dict[str, str], body: str) -> List[str]:
    clues: List[str] = []
    for key in ("Server", "X-Powered-By", "Via"):
        value = headers.get(key)
        if value and "/" in value:
            clues.append(f"{key}:{value}")
    for match in GENERATOR_RE.findall(body):
        clues.append(match.strip())
    for match in re.findall(r"version[\s:=\"']+([0-9.]+)", body, re.IGNORECASE):
        clues.append(f"Version hint: {match}")
    return clues[:10]


def _detect_technologies(headers: Dict[str, str], body: str) -> List[str]:
    techs: List[str] = []
    if WORDPRESS_RE.search(body):
        techs.append("WordPress")
    if DRUPAL_RE.search(body):
        techs.append("Drupal")
    if JOOMLA_RE.search(body):
        techs.append("Joomla")
    if DJANGO_RE.search(body):
        techs.append("Django")
    if LARAVEL_RE.search(body):
        techs.append("Laravel")
    if REACT_RE.search(body):
        techs.append("React")
    if ANGULAR_RE.search(body):
        techs.append("Angular")
    if VUE_RE.search(body):
        techs.append("Vue.js")
    powered = headers.get("X-Powered-By")
    if powered:
        techs.append(powered)
    server = headers.get("Server")
    if server:
        techs.append(server)
    return list(dict.fromkeys(techs))


def _fetch_url(url: str, timeout: float) -> requests.Response:
    return requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout, allow_redirects=True)


def _check_interesting(parsed, timeout: float) -> List[str]:
    notes: List[str] = []
    base = parsed.scheme + "://" + parsed.netloc
    for path, label in INTERESTING_PATHS:
        check_url = urljoin(base, path)
        try:
            resp = _fetch_url(check_url, timeout)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and resp.text.strip():
            if len(resp.text) > 120:
                snippet = resp.text[:120] + "..."
            else:
                snippet = resp.text
            notes.append(f"{label} exposed ({check_url})")
            if label == "Robots file":
                preview = snippet.replace("\n", " | ")
                notes.append(f"Robots preview: {preview}")
    return notes


def fingerprint_url(url: str, timeout: float = 8.0, include_interesting: bool = True) -> Fingerprint:
    target = _clean_url(url)
    parsed = urlparse(target)
    headers: Dict[str, str] = {}
    technologies: List[str] = []
    versions: List[str] = []
    missing_headers: List[str] = []
    title = ""
    interesting: List[str] = []
    certificate = _get_certificate_description(parsed)

    try:
        resp = _fetch_url(target, timeout)
        headers = dict(resp.headers)
        status = resp.status_code
        body = resp.text
    except requests.RequestException as exc:
        return Fingerprint(
            url=target,
            status=None,
            headers={},
            technologies=[],
            versions=[],
            missing_headers=SECURITY_HEADERS,
            title="",
            interesting=[],
            certificate=certificate,
            error=str(exc),
        )

    if include_interesting:
        interesting = _check_interesting(parsed, timeout)

    missing_headers = [h for h in SECURITY_HEADERS if h not in headers]
    versions = _extract_versions(headers, body)
    technologies = _detect_technologies(headers, body)
    title_match = TITLE_RE.search(body)
    if title_match:
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()

    return Fingerprint(
        url=target,
        status=status,
        headers=headers,
        technologies=technologies,
        versions=versions,
        missing_headers=missing_headers,
        title=title,
        interesting=interesting,
        certificate=certificate,
    )


def export_fingerprints(fingerprints: Iterable[Fingerprint]) -> str:
    serializable = []
    for fp in fingerprints:
        serializable.append(
            {
                "url": fp.url,
                "status": fp.status,
                "headers": fp.headers,
                "technologies": fp.technologies,
                "versions": fp.versions,
                "missing_headers": fp.missing_headers,
                "title": fp.title,
                "interesting": fp.interesting,
                "certificate": fp.certificate,
                "error": fp.error,
            }
        )
    return json.dumps(serializable, indent=2)
