"""Compliance scanner: Tanzania PDPA 2022, TCRA SMS, RFC 8058 unsubscribe."""

import re
from pathlib import Path

from . import BaseScanner, load_ignore_patterns, is_ignored
from vibe_coding_qa import Finding, Severity


class ComplianceScanner(BaseScanner):
    module = "compliance"

    def scan(self) -> list[Finding]:
        ignore = load_ignore_patterns(self.repo)
        self._scan_privacy_consent(ignore)
        self._scan_unsubscribe(ignore)
        self._scan_sms_opt_out(ignore)
        self._scan_dpo_and_register(ignore)
        return self.findings

    def _scan_privacy_consent(self, ignore: list[str]) -> None:
        html_files = [
            p for p in (list(self.repo.rglob("*.html")) + list(self.repo.rglob("*.tsx")) + list(self.repo.rglob("*.jsx")) + list(self.repo.rglob("*.vue")) + list(self.repo.rglob("*.svelte")))
            if "vcqa-reports" not in p.parts and "__pycache__" not in p.parts and ".git" not in p.parts and "node_modules" not in p.parts and not is_ignored(p, self.repo, ignore)
        ]
        if not html_files:
            return
        consent_found = False
        explicit_opt_in_found = False
        pre_ticked_found = False
        for path in html_files:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if "consent" in text or "privacy" in text or "data protection" in text:
                consent_found = True
            if re.search(r"checkbox[^\n]{0,200}?(checked|defaultchecked|checked=\"true\"|checked={true})", text, re.IGNORECASE):
                pre_ticked_found = True
            if re.search(r"checkbox[^\n]{0,200}?\b(required|must)\b", text, re.IGNORECASE) and not pre_ticked_found:
                explicit_opt_in_found = True
        if not consent_found:
            self.add(
                rule="privacy-consent-missing",
                severity=Severity.HIGH,
                file=html_files[0],
                line=1,
                message="No privacy or consent disclosure found in UI files.",
                suggestion="Add a clear disclosure naming the data controller and purpose before collecting personal data.",
                confidence="low",
            )
        if pre_ticked_found:
            self.add(
                rule="pre-ticked-consent-checkbox",
                severity=Severity.CRITICAL,
                file=html_files[0],
                line=1,
                message="Pre-ticked consent checkbox detected; this violates Tanzania PDPA 2022.",
                suggestion="Require an explicit affirmative action (unticked checkbox) for consent.",
                confidence="medium",
            )
        if consent_found and not explicit_opt_in_found and not pre_ticked_found:
            self.add(
                rule="explicit-opt-in-unverified",
                severity=Severity.MEDIUM,
                file=html_files[0],
                line=1,
                message="Consent language exists but explicit opt-in mechanism could not be verified.",
                suggestion="Use an unticked checkbox and log consent events with timestamp, IP, and version.",
                confidence="low",
            )

    def _scan_unsubscribe(self, ignore: list[str]) -> None:
        for path in self.iter_source_files((".ts", ".tsx", ".js", ".jsx", ".py")):
            if is_ignored(path, self.repo, ignore):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if "list-unsubscribe" in text or "unsubscribe" in text:
                for i, raw in enumerate(text.splitlines(), 1):
                    lowered = raw.lower()
                    if "list-unsubscribe-post" in lowered:
                        if "one-click" in lowered or "one click" in lowered:
                            self.add(
                                rule="rfc8058-one-click-present",
                                severity=Severity.INFO,
                                file=path,
                                line=i,
                                message="RFC 8058 one-click unsubscribe header detected.",
                                suggestion="Ensure the endpoint returns 200 immediately and adds the address to a suppression list within 24 hours.",
                                confidence="medium",
                            )
                            return
                self.add(
                    rule="rfc8058-list-unsubscribe-incomplete",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=1,
                    message="List-Unsubscribe detected but RFC 8058 List-Unsubscribe-Post: List-Unsubscribe=One-Click not found.",
                    suggestion="Add both List-Unsubscribe and List-Unsubscribe-Post headers to transactional emails.",
                    confidence="low",
                )
                return
        self.add(
            rule="rfc8058-unsubscribe-missing",
            severity=Severity.MEDIUM,
            file=self.repo,
            line=1,
            message="No unsubscribe mechanism detected for email functionality.",
            suggestion="Add List-Unsubscribe and List-Unsubscribe-Post headers to automated emails.",
            confidence="low",
        )

    def _scan_sms_opt_out(self, ignore: list[str]) -> None:
        for path in self.iter_source_files((".ts", ".tsx", ".js", ".jsx", ".py")):
            if is_ignored(path, self.repo, ignore):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if "sms" in text or "notify africa" in text or "beem" in text:
                if "stop" in text or "ondoa" in text:
                    self.add(
                        rule="sms-opt-out-present",
                        severity=Severity.INFO,
                        file=path,
                        line=1,
                        message="SMS opt-out keywords (STOP/ONDOA) detected.",
                        suggestion="Verify opt-out replies are processed automatically and synced to a suppression list within 24 hours.",
                        confidence="low",
                    )
                    return
                self.add(
                    rule="sms-opt-out-missing",
                    severity=Severity.HIGH,
                    file=path,
                    line=1,
                    message="SMS integration detected without STOP/ONDOA opt-out handling.",
                    suggestion="Include STOP and ONDOA opt-out instructions and automate suppression.",
                    confidence="low",
                )
                return

    def _scan_dpo_and_register(self, ignore: list[str]) -> None:
        md_files = [p for p in self.repo.rglob("*.md") if not is_ignored(p, self.repo, ignore)]
        has_dpo = False
        has_pdpc_register = False
        for path in md_files:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if "data protection officer" in text or "dpo" in text:
                has_dpo = True
            if "personal data protection commission" in text or "pdpc" in text:
                has_pdpc_register = True
        if not has_dpo:
            self.add(
                rule="dpo-not-documented",
                severity=Severity.MEDIUM,
                file=self.repo / "README.md" if (self.repo / "README.md").is_file() else self.repo,
                line=1,
                message="No Data Protection Officer documented.",
                suggestion="Document a DPO and publish contact details for privacy inquiries.",
                confidence="low",
            )
        if not has_pdpc_register:
            self.add(
                rule="pdpc-registration-not-documented",
                severity=Severity.MEDIUM,
                file=self.repo / "README.md" if (self.repo / "README.md").is_file() else self.repo,
                line=1,
                message="PDPC data controller registration is not documented.",
                suggestion="Register with the Tanzania PDPC and document the registration certificate.",
                confidence="low",
            )
