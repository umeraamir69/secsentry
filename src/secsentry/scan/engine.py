"""Orchestrate detectors → structural verify → classify → aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from secsentry.classify.heuristic import classify
from secsentry.detectors.registry import detect
from secsentry.git.blobs import is_git_repo
from secsentry.git.run import git
from secsentry.models import Finding, fingerprint, mask_secret
from secsentry.scan.aggregate import Secret, group, rank
from secsentry.scan.ignore import is_allowlisted, load_allowlist
from secsentry.scan.staged import staged_text
from secsentry.scan.working_tree import iter_text_files
from secsentry.verify.structural import structural_ok

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ScanReport:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    blobs_scanned: int = 0
    commits_scanned: int = 0
    repo: str = ""
    allowlisted: int = 0

    @property
    def secrets(self) -> list[Secret]:
        return group(self.findings)

    def counts(self) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for s in self.secrets:
            key = s.severity.lower()
            if key in out:
                out[key] += 1
        return out

    def should_fail(self, fail_on: str) -> bool:
        threshold = SEVERITY_RANK.get(fail_on.lower(), 3)
        return any(rank(f.severity) >= threshold for f in self.findings)


@dataclass
class ScanContext:
    findings: list[Finding] = field(default_factory=list)
    seen_fp_path: set[tuple[str, str, int]] = field(default_factory=set)
    head_blob_oids: set[str] = field(default_factory=set)
    allowed: set[str] = field(default_factory=set)
    files_scanned: int = 0
    blobs_scanned: int = 0
    commits_scanned: int = 0
    allowlisted: int = 0

    def add_occurrence(self, base: Finding, **kwargs) -> None:
        f = Finding(**{**base.__dict__, **kwargs})
        if is_allowlisted(f.fingerprint, self.allowed):
            self.allowlisted += 1
            return
        key = (f.fingerprint, f.path, f.line)
        if key in self.seen_fp_path:
            return
        self.seen_fp_path.add(key)
        self.findings.append(f)


def findings_from_text(
    ctx: ScanContext,
    *,
    path: str,
    text: str,
    blob_oid: str = "",
) -> list[Finding]:
    found: list[Finding] = []
    for hit in detect(text, path):
        ok = structural_ok(hit.secret_type, hit.secret)
        decision = classify(path=path, secret_type=hit.secret_type, secret=hit.secret, structural=ok)
        if not decision.keep:
            continue
        found.append(
            Finding(
                secret_type=hit.secret_type,
                severity=hit.severity,
                confidence=decision.confidence,
                path=path,
                line=hit.line,
                column=hit.column,
                masked=mask_secret(hit.secret),
                fingerprint=fingerprint(hit.secret),
                blob_oid=blob_oid,
                structural_ok=ok,
                entropy=hit.entropy,
                why=decision.why,
            )
        )
    return found


def _head_blob_oids(repo: Path) -> set[str]:
    oids: set[str] = set()
    try:
        for line in git(repo, "ls-tree", "-r", "--full-tree", "HEAD").splitlines():
            meta, _, _path = line.partition("\t")
            bits = meta.split()
            if len(bits) >= 3 and bits[1] == "blob":
                oids.add(bits[2])
    except Exception:
        pass
    return oids


def run_scan(
    repo: Path,
    *,
    history: bool = False,
    staged: bool = False,
    severity: str | None = None,
    types: list[str] | None = None,
) -> ScanReport:
    repo = repo.resolve()
    ctx = ScanContext(allowed=load_allowlist(repo))

    if staged:
        for path, text in staged_text(repo):
            ctx.files_scanned += 1
            for f in findings_from_text(ctx, path=path, text=text):
                ctx.add_occurrence(f, source="staged")
    else:
        for rel, text, _data in iter_text_files(repo):
            ctx.files_scanned += 1
            for f in findings_from_text(ctx, path=rel, text=text):
                ctx.add_occurrence(f, source="working-tree")

        if history and is_git_repo(repo):
            ctx.head_blob_oids = _head_blob_oids(repo)
            from secsentry.scan.history import scan_history

            scan_history(ctx, repo)
            for f in ctx.findings:
                if f.blob_oid:
                    f.still_in_head = f.blob_oid in ctx.head_blob_oids

    findings = ctx.findings
    if severity:
        threshold = SEVERITY_RANK.get(severity.lower(), 0)
        findings = [f for f in findings if rank(f.severity) >= threshold]
    if types:
        wanted = [t.lower() for t in types]
        findings = [f for f in findings if any(w in f.secret_type.lower() for w in wanted)]

    return ScanReport(
        findings=findings,
        files_scanned=ctx.files_scanned,
        blobs_scanned=ctx.blobs_scanned,
        commits_scanned=ctx.commits_scanned,
        repo=str(repo),
        allowlisted=ctx.allowlisted,
    )
