import subprocess


def ssh_exec(host, command, timeout=60):
    try:
        r = subprocess.run(
            ["ssh", host, command],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "SSH command timed out", -1
    except FileNotFoundError:
        return "", "ssh not found", -1
    except Exception as e:
        return "", str(e), -1


def scp_to_remote(host, local, remote):
    try:
        r = subprocess.run(
            ["scp", "-r", local, f"{host}:{remote}"],
            capture_output=True, text=True, timeout=30
        )
        return r.returncode == 0
    except Exception as e:
        print(f"  SCP error: {e}")
        return False


def scp_from_remote(host, remote, local):
    try:
        r = subprocess.run(
            ["scp", "-r", f"{host}:{remote}", local],
            capture_output=True, text=True, timeout=30
        )
        return r.returncode == 0
    except Exception as e:
        print(f"  SCP error: {e}")
        return False
