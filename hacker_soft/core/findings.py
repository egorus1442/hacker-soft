from __future__ import annotations

from collections import Counter
from typing import Iterable

from .models import Category, Confidence, Finding, ModuleResult, Severity


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

CONFIDENCE_WEIGHT = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}

GROUP_EVIDENCE_LIMIT = 50


def collect_findings(results: Iterable[ModuleResult]) -> list[Finding]:
    """Turn raw module output into a report-ready list: deduplicated, grouped, sorted."""
    raw: list[Finding] = []
    for result in results:
        raw.extend(result.findings)
    return sort_findings(group_findings(dedupe_findings(raw)))


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.module, finding.title, finding.target, finding.severity.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def group_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse one repeated problem across many hosts into a single record."""
    groups: dict[tuple[str, str, str, str], list[Finding]] = {}
    order: list[tuple[str, str, str, str]] = []
    for finding in findings:
        key = (finding.module, finding.title, finding.severity.value, finding.category.value)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    grouped: list[Finding] = []
    for key in order:
        members = groups[key]
        if len(members) == 1:
            grouped.append(members[0])
            continue
        grouped.append(merge_group(members))
    return grouped


def merge_group(members: list[Finding]) -> Finding:
    first = members[0]
    targets = []
    for member in members:
        for target in member.all_targets:
            if target not in targets:
                targets.append(target)

    evidence_by_target: dict[str, object] = {}
    for member in members[:GROUP_EVIDENCE_LIMIT]:
        if member.evidence:
            evidence_by_target[member.target] = member.evidence
    evidence: dict[str, object] = {"affected_count": len(targets)}
    if evidence_by_target:
        evidence["by_target"] = evidence_by_target
    if len(members) > GROUP_EVIDENCE_LIMIT:
        evidence["evidence_truncated"] = (
            f"подробности показаны для первых {GROUP_EVIDENCE_LIMIT} целей из {len(members)}"
        )

    references: list[str] = []
    for member in members:
        for reference in member.references:
            if reference not in references:
                references.append(reference)

    confidence = min((member.confidence for member in members), key=lambda item: CONFIDENCE_WEIGHT[item])
    return Finding(
        module=first.module,
        title=first.title,
        severity=first.severity,
        confidence=confidence,
        target=summarize_targets(targets),
        evidence=evidence,
        recommendation=first.recommendation,
        explanation=first.explanation,
        impact=first.impact,
        fix=first.fix,
        references=references,
        category=first.category,
        targets=targets,
    )


def summarize_targets(targets: list[str]) -> str:
    if len(targets) <= 2:
        return ", ".join(targets)
    return f"{targets[0]} и еще {len(targets) - 1}"


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            -len(item.all_targets),
            item.title,
        ),
    )


def issues(findings: Iterable[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.category == Category.ISSUE]


def inventory(findings: Iterable[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.category == Category.INVENTORY]


def diagnostics(findings: Iterable[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.category == Category.DIAGNOSTIC]


def severity_counter(findings: Iterable[Finding]) -> Counter:
    return Counter(finding.severity.value for finding in findings)


def risk_score(findings: Iterable[Finding]) -> int:
    """Weigh severity by confidence and by how much of the surface is affected."""
    score = 0.0
    for finding in issues(findings):
        spread = min(3.0, 1.0 + (len(finding.all_targets) - 1) * 0.15)
        score += SEVERITY_WEIGHT[finding.severity] * CONFIDENCE_WEIGHT[finding.confidence] * spread
    return int(round(min(100.0, score)))


def priority_findings(findings: Iterable[Finding], limit: int = 3) -> list[Finding]:
    """Only real problems belong in "what matters now", ranked by severity and confidence."""
    ranked = sorted(
        issues(findings),
        key=lambda item: (
            -SEVERITY_WEIGHT[item.severity] * CONFIDENCE_WEIGHT[item.confidence],
            SEVERITY_ORDER[item.severity],
            item.title,
        ),
    )
    return ranked[:limit]
