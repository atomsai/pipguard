"""pipguard CLI — command-line interface."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from pipguard import __version__
from pipguard.models.finding import Finding
from pipguard.models.verdict import Verdict


def _blocked_reason_from_rule(rule_id: str) -> str:
    mapping = {
        "PTH-EXEC": "Executable .pth file found",
        "STARTUP-HOOK": "Suspicious startup hook file found",
        "IMPORT-TIME-SIDE-EFFECT": "Suspicious import-time behavior detected",
        "ENV-ENUM": "Enumerates environment variables",
        "SECRET-PATH-READ": "Reads sensitive local credential paths",
        "EXFIL-SINK": "Sends data over outbound network sinks",
        "OBFUSCATION": "Uses payload obfuscation primitives",
        "DYNAMIC-EXEC": "Uses dynamic execution primitives (exec/eval/compile)",
        "SUSPICIOUS-SUBPROCESS": "Spawns suspicious subprocess/network tooling",
        "SOURCE-TO-SINK": "Contains source-to-sink secret exfil chain",
        "SOURCE-TO-SINK-FUNCTION": "Contains function-level source-to-sink secret exfil chain",
        "IOC-FILENAME": "Matches known IOC filename marker",
        "IOC-STRING-MARKER": "Matches known IOC string/domain marker",
        "IOC-DIRECTORY": "Matches known IOC directory marker",
        "IOC-PACKAGE": "Matches known IOC package/version marker",
        "IOC-RECORD": "Matches IOC markers in RECORD metadata",
        "IOC-WHEEL-META": "Matches IOC markers in wheel metadata",
    }
    return mapping.get(rule_id, f"Triggered rule: {rule_id}")


def _artifact_reason_bullets(findings: list[Finding]) -> list[str]:
    unique_reasons: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        reason = _blocked_reason_from_rule(finding.rule_id)
        if reason not in seen:
            seen.add(reason)
            unique_reasons.append(reason)
    return unique_reasons


def _print_blocked_install_summary(
    spec: str, blocked_findings_by_artifact: dict[str, list[Finding]], json_out: str | None
) -> None:
    all_findings = [f for fs in blocked_findings_by_artifact.values() for f in fs]
    has_critical = any(f.severity == "critical" for f in all_findings)
    level = "critical" if has_critical else "high"

    print(f"\nBLOCKED [{level}]")
    print(f"Package: {spec}")
    print("Blocked artifacts and reasons:")
    for artifact_name, artifact_findings in sorted(blocked_findings_by_artifact.items()):
        print(f"  • Artifact: {artifact_name}")
        print("    Why blocked:")
        for reason in _artifact_reason_bullets(artifact_findings)[:6]:
            print(f"      - {reason}")
    print("Nothing was installed.")
    if json_out:
        print(f"Saved report: {json_out}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipguard",
        description="Scan Python packages for supply-chain malware before install.",
    )
    parser.add_argument("--version", action="version", version=f"pipguard {__version__}")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan ---
    p_scan = sub.add_parser("scan", help="Scan a package path (wheel, sdist, or directory)")
    p_scan.add_argument("path", help="Path to wheel, sdist, or unpacked directory")
    p_scan.add_argument("--json-out", help="Save JSON report to this path")
    p_scan.add_argument("--ioc", help="IOC pack name to include")

    # --- install ---
    p_install = sub.add_parser("install", help="Download, scan, then install a package")
    p_install.add_argument("spec", help="Package spec (e.g. 'requests>=2.28')")
    p_install.add_argument("--json-out", help="Save JSON report to this path")
    p_install.add_argument(
        "--policy", choices=["block", "warn"], default="block", help="Enforcement policy"
    )
    p_install.add_argument("--allow-high", action="store_true", help="Allow high-severity findings")
    p_install.add_argument(
        "--allow-critical", action="store_true", help="Allow critical-severity findings"
    )
    p_install.add_argument("--ioc", help="IOC pack name to include")

    # --- doctor ---
    p_doctor = sub.add_parser("doctor", help="Inspect the current environment for compromise")
    p_doctor.add_argument("--json-out", help="Save JSON report to this path")
    p_doctor.add_argument("--ioc", help="IOC pack name to include")

    # --- env-audit ---
    p_audit = sub.add_parser("env-audit", help="Audit credential exposure in current shell")
    p_audit.add_argument("--json-out", help="Save JSON report to this path")

    # --- run ---
    p_run = sub.add_parser(
        "run",
        help="Launch a command with scrubbed environment",
    )
    p_run.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run (after --)")
    p_run.add_argument("--allow-env", action="append", default=[], help="Allow specific env var")
    p_run.add_argument(
        "--allow-env-prefix", action="append", default=[], help="Allow env vars by prefix"
    )
    p_run.add_argument("--profile", action="append", default=[], help="Named profile to apply")
    p_run.add_argument("--strict", action="store_true", help="Strict mode (minimal baseline)")
    p_run.add_argument("--dry-run", action="store_true", help="Show what would happen")
    p_run.add_argument("--print-env", action="store_true", help="Print the full child env")
    p_run.add_argument("--json-out", help="Save JSON report to this path")

    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    from pipguard.core.config import ScanConfig
    from pipguard.output.json_report import save_json_report
    from pipguard.output.terminal import print_scan_report
    from pipguard.scan.engine import scan_directory
    from pipguard.unpack.archive import detect_and_unpack

    target = Path(args.path)
    if not target.exists():
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 1

    config = ScanConfig(ioc_pack=args.ioc)
    try:
        unpacked = detect_and_unpack(target)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    report = scan_directory(unpacked, config)
    print_scan_report(report)

    if args.json_out:
        save_json_report(report, args.json_out)
        print(f"Saved report: {args.json_out}")

    return 1 if report.verdict == Verdict.BLOCKED.value else 0


def _cmd_install(args: argparse.Namespace) -> int:
    from pipguard.core.config import ScanConfig
    from pipguard.download.downloader import download_packages
    from pipguard.download.installer import install_from_local
    from pipguard.download.resolver import list_artifacts
    from pipguard.output.json_report import save_json_report
    from pipguard.output.terminal import print_scan_report
    from pipguard.policies.default import should_block
    from pipguard.scan.engine import scan_directory
    from pipguard.unpack.archive import detect_and_unpack

    config = ScanConfig(
        policy=args.policy,
        allow_high=args.allow_high,
        allow_critical=args.allow_critical,
        ioc_pack=args.ioc,
    )

    with tempfile.TemporaryDirectory(prefix="pipguard_dl_") as tmpdir:
        dl_dir = Path(tmpdir)
        print(f"Downloading {args.spec}...")
        ok, output = download_packages(args.spec, dl_dir)
        if not ok:
            print(f"Download failed:\n{output}", file=sys.stderr)
            return 1

        artifacts = list_artifacts(dl_dir)
        if not artifacts:
            print("No artifacts downloaded.", file=sys.stderr)
            return 1

        any_blocked = False
        combined_findings = []
        blocked_findings_by_artifact: dict[str, list[Finding]] = {}
        for artifact in artifacts:
            try:
                unpacked = detect_and_unpack(artifact)
            except ValueError as exc:
                print(f"Artifact skipped ({artifact.name}): {exc}", file=sys.stderr)
                continue
            report = scan_directory(unpacked, config)
            combined_findings.extend(report.findings)
            print_scan_report(report)
            if should_block(report, config):
                any_blocked = True
                blocked_findings_by_artifact[artifact.name] = list(report.findings)

        if any_blocked:
            if args.json_out:
                from pipguard.models.report import Report

                combined = Report(
                    target=args.spec,
                    verdict=Verdict.BLOCKED.value,
                    findings=combined_findings,
                )
                save_json_report(combined, args.json_out)
            _print_blocked_install_summary(
                spec=args.spec,
                blocked_findings_by_artifact=blocked_findings_by_artifact,
                json_out=args.json_out,
            )
            return 1

        print(f"\nInstalling {args.spec} from scanned artifacts...")
        ok, output = install_from_local(args.spec, dl_dir)
        if not ok:
            print(f"Install failed:\n{output}", file=sys.stderr)
            return 1
        print("Install complete.")

        if args.json_out:
            from pipguard.models.report import Report

            combined = Report(
                target=args.spec,
                verdict=Verdict.ALLOWED.value,
                findings=combined_findings,
            )
            save_json_report(combined, args.json_out)
            print(f"Saved report: {args.json_out}")

    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    from pipguard.core.config import ScanConfig
    from pipguard.doctor.doctor import run_doctor
    from pipguard.output.json_report import save_json_report
    from pipguard.output.terminal import print_doctor_report

    config = ScanConfig(ioc_pack=args.ioc)
    report = run_doctor(config)
    print_doctor_report(report)

    if args.json_out:
        save_json_report(report, args.json_out)
        print(f"Saved report: {args.json_out}")

    return 1 if report.verdict == "review-now" else 0


def _cmd_env_audit(args: argparse.Namespace) -> int:
    from pipguard.output.json_report import save_json_report
    from pipguard.output.terminal import print_env_audit
    from pipguard.runtime.env_audit import run_env_audit

    report = run_env_audit()
    print_env_audit(report)

    if args.json_out:
        save_json_report(report, args.json_out)
        print(f"Saved report: {args.json_out}")

    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    from pipguard.output.json_report import save_json_report
    from pipguard.output.terminal import print_run_result
    from pipguard.runtime.profiles import list_profiles
    from pipguard.runtime.runner import run_command

    cmd = args.cmd
    # Strip leading '--' if present
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd and not args.dry_run:
        print("Error: no command provided. Use: pipguard run -- <command>", file=sys.stderr)
        return 1

    valid_profiles = set(list_profiles())
    unknown_profiles = [name for name in args.profile if name not in valid_profiles]
    if unknown_profiles:
        print(
            f"Error: unknown profile(s): {', '.join(unknown_profiles)}. "
            f"Available: {', '.join(sorted(valid_profiles))}",
            file=sys.stderr,
        )
        return 1

    result = run_command(
        cmd,
        allow_env=args.allow_env,
        allow_env_prefix=args.allow_env_prefix,
        profiles=args.profile,
        strict=args.strict,
        dry_run=args.dry_run,
    )

    print_run_result(result)

    if args.print_env:
        print("Full child environment:")
        for k, v in sorted(result.child_env.items()):
            print(f"  {k}={v[:80]}{'...' if len(v) > 80 else ''}")

    if args.json_out:
        from pipguard.models.report import Report

        report = Report(
            target=" ".join(cmd) if cmd else "(dry-run)",
            verdict="scrubbed",
            summary={
                "inherited": result.inherited,
                "blocked": result.blocked,
                "dry_run": result.dry_run,
            },
        )
        save_json_report(report, args.json_out)
        print(f"Saved report: {args.json_out}")

    return result.exit_code


def main() -> None:
    """Entry point for pipguard CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "scan": _cmd_scan,
        "install": _cmd_install,
        "doctor": _cmd_doctor,
        "env-audit": _cmd_env_audit,
        "run": _cmd_run,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))
