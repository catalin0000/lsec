#!/usr/bin/env python3

import argparse
import sys
import os
import json

from modules.scan import run_scan
from modules.parser import parse_nmap
from modules.ssh import scp_from_remote


def cmd_scan(args):
    run_scan(
        targets_file=args.file,
        jump_host=args.jump_host,
        parallelism=args.parallel,
        dry_run=args.dry_run,
    )


def cmd_parse(args):
    parse_nmap(
        scan_dir=args.dir,
        output=args.output,
        probe_tls=args.probe,
        jump_host=args.jump_host,
    )


def cmd_retrieve(args):
    manifest_path = "scan/.remote-manifest.json"

    if not os.path.isfile(manifest_path):
        print(f"[-] No remote manifest found: {manifest_path}")
        print("    Run a remote scan first:")
        print("      lsec scan -f targets.txt --jump-host <host>")
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    jump_host = args.jump_host or manifest.get("jump_host")
    remote_path = manifest.get("remote_path")

    if not jump_host or not remote_path:
        print("[-] Invalid remote manifest (missing jump_host or remote_path)")
        sys.exit(1)

    local_output = args.output
    remote_nmap_output = os.path.join(remote_path, "nmap-output")
    local_nmap_output = os.path.join(local_output, "nmap-output")

    print(f"[*] Retrieving from {jump_host}:{remote_nmap_output}")
    print(f"[*] Destination: {local_nmap_output}")

    os.makedirs(local_nmap_output, exist_ok=True)

    success = scp_from_remote(jump_host, remote_nmap_output + "/", local_nmap_output + "/")

    if success:
        print(f"[+] Results retrieved to {local_nmap_output}")
    else:
        print("[-] Retrieve failed.")
        print("    The remote scan may still be running or no files exist yet.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="lsec",
        description="Modular security assessment tool",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run nmap scans against targets")
    scan_p.add_argument("-f", "--file", required=True,
                        help="File with targets (one per line: IP, CIDR, hostname)")
    scan_p.add_argument("--jump-host",
                        help="SSH jump host for remote scanning (SSH config hostname)")
    scan_p.add_argument("--parallel", type=int, default=4,
                        help="Parallel jobs (default: 4)")
    scan_p.add_argument("--dry-run", action="store_true",
                        help="Generate commands file but do not execute")
    scan_p.set_defaults(func=cmd_scan)

    parse_p = sub.add_parser("parse", help="Parse nmap XML output into structured data")
    parse_p.add_argument("-d", "--dir", default="scan",
                         help="Nmap XML input directory (default: scan/)")
    parse_p.add_argument("-o", "--output",
                         help="Output path for parsed JSON (default: parsed.json)")
    parse_p.add_argument("--probe", action="store_true",
                         help="Actively probe TCP services for TLS")
    parse_p.add_argument("--jump-host",
                         help="Use SSH jump host for remote TLS probing")
    parse_p.set_defaults(func=cmd_parse)

    ret_p = sub.add_parser("retrieve",
                           help="Retrieve remote scan results from jump host")
    ret_p.add_argument("--jump-host",
                       help="SSH jump host (overrides manifest)")
    ret_p.add_argument("-o", "--output", default="scan",
                       help="Local output directory (default: scan/)")
    ret_p.set_defaults(func=cmd_retrieve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
