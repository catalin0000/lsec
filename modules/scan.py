import os
import sys
import json
import subprocess
from datetime import datetime

NMAP_ARGS_TCP = "-sV -sC --top-ports 1000 -T4 -oA"
NMAP_ARGS_UDP = "-sU -sV -sC --top-ports 100 -T4 -oA"
DEFAULT_PARALLEL = 4

SCAN_DIR = "scan"
NMAP_OUTPUT_DIR = os.path.join(SCAN_DIR, "nmap-output")
COMMANDS_FILE = os.path.join(SCAN_DIR, "nmap-commands.txt")
TARGETS_FILE = os.path.join(SCAN_DIR, "nmap-targets.txt")
REMOTE_MANIFEST = os.path.join(SCAN_DIR, ".remote-manifest.json")
REMOTE_BASE = "/tmp/lsec-scan"


def _sanitize_target(target):
    return target.replace("/", "_").replace(" ", "_").replace(":", "_")


def _read_targets(targets_file):
    if not os.path.isfile(targets_file):
        print(f"[-] Targets file not found: {targets_file}")
        sys.exit(1)
    targets = []
    with open(targets_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    if not targets:
        print("[-] No targets found in file (empty or all comments)")
        sys.exit(1)
    return targets


def _check_tool(tool):
    try:
        subprocess.run(["which", tool], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _run_in_tmux(session_name, command, workdir=None):
    if workdir:
        full_cmd = f"cd {workdir} && {command}"
    else:
        full_cmd = command
    try:
        subprocess.run(
            ["tmux", "new-session", "-d", "-s", session_name, full_cmd],
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _run_nohup(command, log_file):
    nohup_cmd = f"nohup {command} > {log_file} 2>&1 &"
    subprocess.run(["bash", "-c", nohup_cmd])


def _generate_commands(targets, nmap_output_dir, nmap_args_tcp, nmap_args_udp):
    lines = []
    for target in targets:
        sanitized = _sanitize_target(target)
        tcp_cmd = f"nmap {nmap_args_tcp} {nmap_output_dir}/{sanitized}.tcp {target}"
        udp_cmd = f"nmap {nmap_args_udp} {nmap_output_dir}/{sanitized}.udp {target}"
        lines.append(tcp_cmd)
        lines.append(udp_cmd)
    return lines


def _run_local(targets, parallelism, dry_run):
    has_tmux = _check_tool("tmux")
    has_parallel = _check_tool("parallel")

    if not has_parallel and not dry_run:
        print("[!] GNU parallel not found, falling back to sequential execution")

    if not has_tmux and not dry_run:
        print("[!] tmux not found, falling back to nohup")

    os.makedirs(NMAP_OUTPUT_DIR, exist_ok=True)

    with open(TARGETS_FILE, "w") as f:
        for t in targets:
            f.write(t + "\n")

    cmd_lines = _generate_commands(targets, NMAP_OUTPUT_DIR, NMAP_ARGS_TCP, NMAP_ARGS_UDP)
    with open(COMMANDS_FILE, "w") as f:
        for line in cmd_lines:
            f.write(line + "\n")

    if dry_run:
        print(f"[*] Dry run — {len(cmd_lines)} commands written to {COMMANDS_FILE}")
        print(f"[*] Would run: parallel -j {parallelism} < {COMMANDS_FILE}")
        print()
        print("[*] Generated commands:")
        for line in cmd_lines:
            print(f"    {line}")
        return

    print(f"[+] Generated {len(cmd_lines)} nmap commands ({len(targets)} targets x TCP+UDP)")
    print(f"[+] Commands file: {COMMANDS_FILE}")

    parallel_cmd = f"parallel -j {parallelism} < {COMMANDS_FILE}"

    if has_tmux and has_parallel:
        session_name = "lsec-scan"
        if _run_in_tmux(session_name, parallel_cmd):
            print(f"[+] Launched in tmux session '{session_name}'")
            print(f"[+]   Attach:  tmux attach -t {session_name}")
            print(f"[+]   Detach:  Ctrl+B, d")
            return

    if has_parallel:
        _run_nohup(parallel_cmd, f"{SCAN_DIR}/parallel.log")
        print(f"[+] Running parallel in background (log: {SCAN_DIR}/parallel.log)")
        print(f"[+]   Monitor: tail -f {SCAN_DIR}/parallel.log")
    else:
        print("[*] Running sequentially in background (this may take a while)...")
        seq_cmd = f"while IFS= read -r cmd; do eval \"$cmd\"; done < {COMMANDS_FILE}"
        _run_nohup(seq_cmd, f"{SCAN_DIR}/sequential.log")
        print(f"[+]   Monitor: tail -f {SCAN_DIR}/sequential.log")


def _run_remote(targets, jump_host, parallelism, dry_run):
    remote_path = REMOTE_BASE
    remote_nmap_output = os.path.join(remote_path, "nmap-output")
    remote_commands = os.path.join(remote_path, "nmap-commands.txt")
    remote_targets = os.path.join(remote_path, "nmap-targets.txt")

    if not dry_run:
        os.makedirs(NMAP_OUTPUT_DIR, exist_ok=True)

    with open(TARGETS_FILE, "w") as f:
        for t in targets:
            f.write(t + "\n")

    cmd_lines = _generate_commands(targets, remote_nmap_output, NMAP_ARGS_TCP, NMAP_ARGS_UDP)
    with open(COMMANDS_FILE, "w") as f:
        for line in cmd_lines:
            f.write(line + "\n")

    manifest = {
        "jump_host": jump_host,
        "remote_path": remote_path,
        "started_at": datetime.now().isoformat(),
        "target_count": len(targets),
        "command_count": len(cmd_lines),
    }
    with open(REMOTE_MANIFEST, "w") as f:
        json.dump(manifest, f, indent=2)

    if dry_run:
        print(f"[*] Dry run — remote jump host: {jump_host}")
        print(f"[*] Remote path: {remote_path}")
        print(f"[*] {len(cmd_lines)} commands in {COMMANDS_FILE}")
        print(f"[*] Would run on remote: parallel -j {parallelism} < {remote_commands}")
        return

    from modules.ssh import ssh_exec, scp_to_remote

    print(f"[+] Setting up remote directory on {jump_host}...")
    ok, _, _ = ssh_exec(jump_host, f"mkdir -p {remote_nmap_output}")
    if not ok:
        print(f"[-] Failed to connect to {jump_host}")
        print("    Check your SSH config and that the host is reachable.")
        sys.exit(1)

    print(f"[+] Uploading targets file...")
    scp_to_remote(jump_host, TARGETS_FILE, remote_targets)

    print(f"[+] Uploading commands file...")
    scp_to_remote(jump_host, COMMANDS_FILE, remote_commands)

    print(f"[+] Launching scan on {jump_host}...")
    cmd = f"cd {remote_path} && parallel -j {parallelism} < {remote_commands}"

    has_tmux_remote, _, _ = ssh_exec(jump_host, "which tmux")
    if has_tmux_remote:
        tmux_cmd = f"tmux new-session -d -s lsec-scan '{cmd}'"
        _, stderr, rc = ssh_exec(jump_host, tmux_cmd)
        if rc == 0:
            print(f"[+] Running in tmux session 'lsec-scan' on {jump_host}")
            print(f"[+]   Check: ssh {jump_host} 'tmux capture-pane -t lsec-scan -p'")
            print(f"[+]   Attach: ssh {jump_host} -t 'tmux attach -t lsec-scan'")
        else:
            print(f"[!] tmux launch failed ({stderr.strip()}), falling back to nohup")
            nohup_cmd = f"{cmd} > {remote_path}/parallel.log 2>&1 &"
            ssh_exec(jump_host, nohup_cmd)
            print(f"[+] Running in background via nohup on {jump_host}")
            print(f"[+]   Check: ssh {jump_host} 'tail -f {remote_path}/parallel.log'")
    else:
        nohup_cmd = f"cd {remote_path} && nohup {cmd} > {remote_path}/parallel.log 2>&1 &"
        ssh_exec(jump_host, nohup_cmd)
        print(f"[+] Running in background via nohup on {jump_host}")
        print(f"[+]   Check: ssh {jump_host} 'tail -f {remote_path}/parallel.log'")

    print(f"\n[!] Retrieve results later:")
    print(f"    lsec retrieve --jump-host {jump_host}")


def run_scan(targets_file, jump_host=None, parallelism=DEFAULT_PARALLEL, dry_run=False):
    targets = _read_targets(targets_file)

    if os.path.isdir(SCAN_DIR) and not dry_run:
        if os.path.isfile(REMOTE_MANIFEST):
            print(f"[!] Overwriting existing remote scan in {SCAN_DIR}/")
        else:
            print(f"[*] Using existing {SCAN_DIR}/ directory")

    if jump_host:
        _run_remote(targets, jump_host, parallelism, dry_run)
    else:
        _run_local(targets, parallelism, dry_run)
