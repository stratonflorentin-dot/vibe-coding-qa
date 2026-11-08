"""Scan profiles.

A profile is not a label: it selects which scanner modules actually run, whether
the isolated test suite and OSV lookups are attempted, whether optional AI review
is requested, and the minimum score the release gate enforces. All of these map
onto real engine parameters.
"""

from dataclasses import dataclass

ALL_MODULES: tuple[str, ...] = (
    "security",
    "quality",
    "database",
    "infrastructure",
    "performance",
    "compliance",
    "dependencies",
)


@dataclass(frozen=True)
class ScanProfile:
    key: str
    name: str
    description: str
    modules: tuple[str, ...]
    run_tests: bool
    osv: bool
    ai_review: bool
    minimum_score: int
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "modules": list(self.modules),
            "run_tests": self.run_tests,
            "osv": self.osv,
            "ai_review": self.ai_review,
            "minimum_score": self.minimum_score,
            "notes": list(self.notes),
        }


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        key="quick",
        name="Quick Scan",
        description="Fast static pass over security and dependency risks. No tests, no network lookups.",
        modules=("security", "dependencies"),
        run_tests=False,
        osv=False,
        ai_review=False,
        minimum_score=50,
        notes=("Static analysis only.", "No test execution.", "No OSV advisory lookups."),
    ),
    "standard": ScanProfile(
        key="standard",
        name="Standard Scan",
        description="All static scanners plus optional OSV advisory lookups and isolated tests when permitted.",
        modules=ALL_MODULES,
        run_tests=True,
        osv=True,
        ai_review=False,
        minimum_score=60,
        notes=("Runs every static scanner.", "Tests run only with explicit permission."),
    ),
    "deep": ScanProfile(
        key="deep",
        name="Deep Scan",
        description="Everything in Standard plus optional AI review of critical and high findings.",
        modules=ALL_MODULES,
        run_tests=True,
        osv=True,
        ai_review=True,
        minimum_score=60,
        notes=("Requires a configured AI provider for the AI stage.",),
    ),
    "production_readiness": ScanProfile(
        key="production_readiness",
        name="Production Readiness",
        description="Full audit with a stricter release threshold; unverified tests block a PASS.",
        modules=ALL_MODULES,
        run_tests=True,
        osv=True,
        ai_review=False,
        minimum_score=75,
        notes=("Minimum score 75.", "Requires a verified test run for a PASS verdict."),
    ),
    "security_audit": ScanProfile(
        key="security_audit",
        name="Security Audit",
        description="Focused on exploitable risk: security, database exposure, infrastructure and compliance.",
        modules=("security", "database", "infrastructure", "compliance", "dependencies"),
        run_tests=False,
        osv=True,
        ai_review=True,
        minimum_score=65,
        notes=("Skips quality and performance scanners.",),
    ),
    "supabase_audit": ScanProfile(
        key="supabase_audit",
        name="Supabase Audit",
        description="Row-level-security and data-exposure focused audit.",
        modules=("database", "security", "compliance", "infrastructure"),
        run_tests=False,
        osv=False,
        ai_review=False,
        minimum_score=60,
        notes=("Emphasises Postgres RLS and client-side data exposure.",),
    ),
    "nextjs_audit": ScanProfile(
        key="nextjs_audit",
        name="Next.js Audit",
        description="Frontend/API security, quality and performance for Next.js and React applications.",
        modules=("security", "quality", "dependencies", "performance", "infrastructure", "compliance"),
        run_tests=True,
        osv=True,
        ai_review=False,
        minimum_score=60,
        notes=("Runs the npm/vitest/jest suite only with explicit permission.",),
    ),
}

DEFAULT_PROFILE = "standard"


def get_profile(key: str | None) -> ScanProfile:
    if not key:
        return PROFILES[DEFAULT_PROFILE]
    profile = PROFILES.get(key)
    if profile is None:
        raise KeyError(key)
    return profile


def list_profiles() -> list[dict]:
    return [profile.to_dict() for profile in PROFILES.values()]
