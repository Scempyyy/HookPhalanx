"""Command-line interface for HookPhalanx."""

import argparse
import json
import sys
from . import __version__
from .analyzer import PhishingAnalyzer
from .server import run_server


def main():
    parser = argparse.ArgumentParser(
        prog="hookphalanx",
        description="HookPhalanx: Zero-Trust Phishing Link Sandbox & Heuristic Threat Inspector"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # scan command
    scan_p = subparsers.add_parser("scan", help="Detonate and analyze a target URL")
    scan_p.add_argument("url", help="Target URL to inspect")
    scan_p.add_argument("--json", action="store_true", help="Output raw JSON results")
    scan_p.add_argument("--no-fetch", action="store_true", help="Perform static URL heuristic checks without network request")
    scan_p.add_argument("--allow-private", action="store_true", help="Allow internal / private network target scanning")

    # serve command
    serve_p = subparsers.add_parser("serve", help="Launch the web-based threat analysis studio")
    serve_p.add_argument("--port", type=int, default=7088, help="Web server port (default: 7088)")
    serve_p.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")

    args = parser.parse_args()

    if args.command == "serve":
        run_server(port=args.port, host=args.host)
        return

    if args.command == "scan":
        analyzer = PhishingAnalyzer(allow_private=args.allow_private)
        result = analyzer.analyze(args.url, fetch_body=not args.no_fetch)

        if args.json:
            print(json.dumps(result, indent=2))
            return

        grade_colors = {
            "MALICIOUS": "\033[91m",  # Red
            "DANGEROUS": "\033[33m",  # Orange/Yellow
            "SUSPICIOUS": "\033[93m", # Bright Yellow
            "SAFE": "\033[92m",       # Green
        }
        reset = "\033[0m"
        bold = "\033[1m"
        cyan = "\033[96m"

        color = grade_colors.get(result["grade"], "")
        print(f"\n{bold}{cyan}=== HookPhalanx Sandbox Detonation Report ==={reset}")
        print(f"{bold}Target URL:{reset}    {result['url']}")
        print(f"{bold}Resolved Host:{reset} {result['hostname']}")
        print(f"{bold}Verdict:{reset}       {color}{bold}{result['grade']}{reset} ({result['score']}/100 Risk Score)")

        print(f"\n{bold}Detected Security Indicators ({len(result['indicators'])}):{reset}")
        if not result["indicators"]:
            print("  ✓ No high-risk heuristics or phishing signatures detected.")
        else:
            for ind in result["indicators"]:
                sev = ind["severity"]
                print(f"  • [{sev}] {bold}{ind['title']}{reset} (+{ind['points']} pts)")
                print(f"    {ind['detail']}")

        if result.get("hops"):
            print(f"\n{bold}Redirection Chain ({len(result['hops'])} hops):{reset}")
            for h in result["hops"]:
                status = h.get("status") or h.get("error")
                print(f"  [{h['hop']}] {h['url']} -> {status}")

        print("")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
