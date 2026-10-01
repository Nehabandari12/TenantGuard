"""Outbound checks on everything that leaves the app: answers, tool arguments, links, log lines.

1. Foreign canaries: tenant-tagged record markers (e.g. GLBX-4A1F0C) belonging to another tenant,
   matched on every decoded view (base64, hex, URL-encoding, reversal, separators) -> block.
   This is the part that "knows the canaries"; TG_EGRESS_CANARY=0 turns it off so the
   benchmark can report B3 without it (otherwise egress and the detector share knowledge).
2. Secrets: credential shapes (sk-..., AKIA...) and SSN / card numbers -> redacted in answers and
   log records.
3. PII: Presidio (or a regex fallback) -> redacted in log records. Answers and tool arguments keep the
   tenant's own customer details on purpose: they are that tenant's data, and a support agent needs a
   customer's email. Other tenants' data never gets that far, because of check 1 and the access layer.
4. Links: markdown links, images and bare URLs are only allowed to approved domains. A tool
   call whose arguments carry a non-approved URL is refused outright.
"""

import re
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urlparse

from tenantguard.decode import views
from tenantguard.identity import Principal

BLOCK_MESSAGE = "[TenantGuard] Response withheld: it contained data that belongs to another tenant."

_SECRET_PATTERNS = {
    "API_KEY": re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    "AWS_KEY_ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"\+?\d[\d ().-]{8,}\d")
_URL = re.compile(r"https?://[^\s)\]>\"']+", re.IGNORECASE)
_MD_LINK = re.compile(r"!?\[([^\]]*)\]\((https?://[^)\s]+)\)", re.IGNORECASE)


@dataclass
class Finding:
    kind: str
    detail: str


@dataclass
class EgressResult:
    text: str
    blocked: bool = False
    findings: list[Finding] = field(default_factory=list)


def _canary_regex(codes: list[str]) -> re.Pattern[str]:
    sep = r"[\W_]{0,3}"
    code_alt = "|".join(sep.join(re.escape(ch) for ch in code) for code in codes)
    hexrun = sep.join(["[0-9A-Fa-f]"] * 6)
    return re.compile(rf"(?<![A-Za-z0-9])({code_alt}){sep}({hexrun})(?![A-Za-z0-9])", re.IGNORECASE)


@lru_cache(maxsize=1)
def _presidio():
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        })
        return AnalyzerEngine(nlp_engine=provider.create_engine())
    except Exception:
        return None


_PRESIDIO_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS"]


class Egress:
    def __init__(self, tenant_codes: dict[str, str], allowed_domains: tuple[str, ...], *, canary_check: bool = True, use_presidio: bool = True) -> None:
        self.tenant_codes = tenant_codes                     # tenant_id -> code
        self.code_owner = {c: t for t, c in tenant_codes.items()}
        self.allowed_domains = allowed_domains
        self.canary_check = canary_check
        self.use_presidio = use_presidio
        self._canary_re = _canary_regex(list(tenant_codes.values())) if tenant_codes else None

    # ---- building blocks -------------------------------------------------------------

    def foreign_markers(self, text: str, principal: Principal) -> list[str]:
        if not self.canary_check or self._canary_re is None:
            return []
        own = self.tenant_codes.get(principal.tenant_id)
        found = []
        for view in views(text):
            for m in self._canary_re.finditer(view):
                code = re.sub(r"[\W_]", "", m.group(1)).upper()
                if code != own and code in self.code_owner:
                    found.append(code + "-" + re.sub(r"[\W_]", "", m.group(2)).upper())
        return sorted(set(found))

    def domain_allowed(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return any(host == d or host.endswith("." + d) for d in self.allowed_domains)

    def redact_secrets(self, text: str) -> tuple[str, list[Finding]]:
        findings = []
        for label, pattern in _SECRET_PATTERNS.items():
            if pattern.search(text):
                findings.append(Finding("secret", label))
                text = pattern.sub(f"[REDACTED:{label}]", text)
        return text, findings

    def redact_pii(self, text: str) -> str:
        engine = _presidio() if self.use_presidio else None
        if engine is not None:
            results = engine.analyze(text=text, language="en", entities=_PRESIDIO_ENTITIES)
            for r in sorted(results, key=lambda r: r.start, reverse=True):
                text = text[: r.start] + f"[REDACTED:{r.entity_type}]" + text[r.end :]
        text = _EMAIL.sub("[REDACTED:EMAIL_ADDRESS]", text)
        text = _PHONE.sub("[REDACTED:PHONE_NUMBER]", text)
        return text

    def strip_links(self, text: str) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []

        def md(m: re.Match) -> str:
            if self.domain_allowed(m.group(2)):
                return m.group(0)
            findings.append(Finding("link", urlparse(m.group(2)).hostname or "?"))
            return f"{m.group(1)} [link removed]"

        text = _MD_LINK.sub(md, text)

        def bare(m: re.Match) -> str:
            if self.domain_allowed(m.group(0)):
                return m.group(0)
            findings.append(Finding("link", urlparse(m.group(0)).hostname or "?"))
            return "[link removed]"

        return _URL.sub(bare, text), findings

    # ---- channel policies ------------------------------------------------------------

    def check_answer(self, text: str, principal: Principal) -> EgressResult:
        foreign = self.foreign_markers(text, principal)
        if foreign:
            return EgressResult(BLOCK_MESSAGE, blocked=True, findings=[Finding("foreign_canary", c) for c in foreign])
        text, f1 = self.strip_links(text)
        text, f2 = self.redact_secrets(text)
        return EgressResult(text, findings=f1 + f2)

    def check_tool_args(self, args: dict, principal: Principal) -> EgressResult:
        flat = " ".join(str(v) for v in args.values())
        foreign = self.foreign_markers(flat, principal)
        if foreign:
            return EgressResult(flat, blocked=True, findings=[Finding("foreign_canary", c) for c in foreign])
        bad = [u for u in _URL.findall(flat) if not self.domain_allowed(u)]
        if bad:
            return EgressResult(flat, blocked=True, findings=[Finding("link", urlparse(u).hostname or "?") for u in bad])
        return EgressResult(flat)

    def redact_for_log(self, text: str, principal: Principal) -> str:
        if self.foreign_markers(text, principal):
            return "[TenantGuard] log line withheld: contained another tenant's data"
        text, _ = self.redact_secrets(text)
        return self.redact_pii(text)
