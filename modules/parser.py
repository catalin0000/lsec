import os
import sys
import json
import ssl
import socket
from datetime import datetime
from xml.etree import ElementTree

TLS_PORTS = {
    443, 465, 636, 989, 990, 992, 993, 994, 995,
    3269, 5061, 6443, 8443, 9443, 4443, 4444, 9090, 10443,
}

TOOL_CMDS = {
    "nuclei": {
        "services": ["http", "https"],
        "cmd_tls": "nuclei -o {outdir}/{host}-{port}.json -u https://{host}:{port}",
        "cmd": "nuclei -o {outdir}/{host}-{port}.json -u http://{host}:{port}",
    },
    "testssl": {
        "cmd": "testssl -oJ {outdir} {host}:{port}",
        "needs_tls": True,
        "match_all_tls": True,
    },
    "ssh-audit": {
        "services": ["ssh"],
        "cmd": "ssh-audit -jj {host} {port} > {outdir}/{host}-{port}.json 2>&1",
    },
    "snmp-check": {
        "services": ["snmp"],
        "cmd": "snmp-check {host} -c public -p {port} > {outdir}/{host}-{port}.txt 2>&1",
    },
    "smtp-user-enum": {
        "services": ["smtp", "smtps"],
        "cmd": "smtp-user-enum -M VRFY -U /usr/share/wordlists/users.txt -t {host} -p {port} > {outdir}/{host}-{port}.txt 2>&1",
    },
    "kerbrute": {
        "services": ["kerberos"],
        "cmd": "kerbrute userenum -d example.com /usr/share/wordlists/users.txt --dc {host}:{port} -o {outdir}/{host}-{port}.txt",
    },
    "nikto": {
        "services": ["http", "https"],
        "cmd_tls": "timeout 180 nikto -ssl -timeout 10 -host {host} -port {port} -output {outdir}/{host}-{port}.txt",
        "cmd": "timeout 180 nikto -timeout 10 -host {host} -port {port} -output {outdir}/{host}-{port}.txt",
    },
    "security-headers": {
        "services": ["http", "https"],
        "cmd_tls": "curl -skI https://{host}:{port} > {outdir}/{host}-{port}.headers.txt 2>&1",
        "cmd": "curl -sI http://{host}:{port} > {outdir}/{host}-{port}.headers.txt 2>&1",
    },
}


def _parse_nmap_xml(xml_path):
    try:
        tree = ElementTree.parse(xml_path)
        root = tree.getroot()
    except ElementTree.ParseError as e:
        print(f"  [!] Skipping malformed XML: {os.path.basename(xml_path)}: {e}")
        return []

    results = []
    for host_elem in root.findall("host"):
        status_el = host_elem.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        addr_el = host_elem.find("address")
        if addr_el is None:
            continue
        host = addr_el.get("addr")

        hostname = ""
        hostnames_el = host_elem.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                name = hn.get("name", "")
                if name:
                    hostname = name
                    break

        os_info = ""
        os_el = host_elem.find("os")
        if os_el is not None:
            for osm in os_el.findall("osmatch"):
                os_info = osm.get("name", "")
                if os_info:
                    break

        ports_el = host_elem.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            port_id = port_el.get("portid")
            protocol = port_el.get("protocol")

            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"

            if state != "open":
                continue

            svc_el = port_el.find("service")
            service = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            tunnel = svc_el.get("tunnel", "") if svc_el is not None else ""

            results.append({
                "host": host,
                "hostname": hostname,
                "os": os_info,
                "port": int(port_id),
                "protocol": protocol,
                "state": state,
                "service": service,
                "product": product,
                "version": version,
                "tunnel": tunnel,
            })

    return results


def _heuristic_tls(service):
    if service["tunnel"] == "ssl":
        return True, "nmap_tunnel"
    if service["service"] in ("https", "ssl/http", "ssl", "tls", "ssl/https"):
        return True, "nmap_service"
    if service["port"] in TLS_PORTS:
        return True, "port_heuristic"
    return False, None


def _probe_tls_local(host, port, timeout=3):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                tls_version = tls.version()
                cert = tls.getpeercert()
                cert_cn = ""
                if cert:
                    for subj in cert.get("subject", []):
                        for key, val in subj:
                            if key == "commonName":
                                cert_cn = val
                return True, {"version": tls_version, "cert_cn": cert_cn}
    except (ssl.SSLError, OSError, socket.timeout, ConnectionRefusedError):
        return False, {}


def _probe_tls_remote(host, port, jump_host, timeout=5):
    from modules.ssh import ssh_exec
    cmd = (
        f"timeout {timeout} bash -c "
        f"'echo | openssl s_client -connect {host}:{port} 2>&1 | head -30'"
    )
    stdout, _, rc = ssh_exec(jump_host, cmd)
    if not stdout:
        return False, {}
    if "CONNECTED" in stdout and "BEGIN CERTIFICATE" in stdout:
        version = ""
        cert_cn = ""
        for line in stdout.splitlines():
            if "TLS" in line or "SSL" in line and "handshake" not in line and ":" in line:
                version = line.strip()
            if "subject=" in line:
                cert_cn = line.split("subject=")[-1].strip()
            if "subject=" in line and "CN = " in line:
                parts = line.split("CN = ")
                if len(parts) > 1:
                    cert_cn = parts[1].split(",")[0].strip()
        return True, {"version": version, "cert_cn": cert_cn}
    return False, {}


def _find_nmap_dir(base_dir):
    if not os.path.isdir(base_dir):
        return None
    candidates = [base_dir, os.path.join(base_dir, "nmap-output")]
    for d in candidates:
        if os.path.isdir(d) and any(f.endswith(".xml") for f in os.listdir(d)):
            return d
    return candidates[-1]


def parse_nmap(scan_dir="scan", output=None, probe_tls=False, jump_host=None):
    nmap_output_dir = _find_nmap_dir(scan_dir)

    if nmap_output_dir is None:
        print(f"[-] Directory not found: {scan_dir}")
        print("    Run a scan first: lsec scan -f targets.txt")
        sys.exit(1)

    xml_files = sorted([
        f for f in os.listdir(nmap_output_dir)
        if f.endswith(".xml")
    ])

    if not xml_files:
        print(f"[-] No .xml files found in {scan_dir} or {scan_dir}/nmap-output/")
        print("    This might mean no scans have completed yet.")
        sys.exit(1)

    print(f"[*] Parsing {len(xml_files)} XML files...")

    all_services = []
    hosts = {}

    for xml_file in xml_files:
        xml_path = os.path.join(nmap_output_dir, xml_file)
        services = _parse_nmap_xml(xml_path)
        for svc in services:
            h = svc["host"]
            if h not in hosts:
                hosts[h] = {
                    "hostname": svc["hostname"],
                    "os": svc["os"],
                    "services": [],
                }
            hosts[h]["services"].append(svc)
            all_services.append(svc)

    if not all_services:
        print("[-] No open services found in any XML files")
        sys.exit(1)

    print(f"[+] Found {len(hosts)} hosts, {len(all_services)} open services")

    tls_confirmed = 0
    for svc in all_services:
        tls, method = _heuristic_tls(svc)
        svc["tls"] = tls
        svc["tls_detected_by"] = method or "none"
        svc["tls_info"] = {}
        if tls:
            tls_confirmed += 1

    if probe_tls:
        print(f"[*] Probing for TLS (heuristics already found {tls_confirmed} services)...")
        for svc in all_services:
            if svc["tls"]:
                continue
            host = svc["host"]
            port = svc["port"]
            if jump_host:
                result, info = _probe_tls_remote(host, port, jump_host)
            else:
                result, info = _probe_tls_local(host, port)
            if result:
                svc["tls"] = True
                svc["tls_detected_by"] = "active_probe"
                svc["tls_info"] = info
                tls_confirmed += 1
                print(f"  [+] TLS confirmed: {host}:{port} ({info.get('version', '?')})")

    if tls_confirmed:
        print(f"[+] Total TLS-enabled services: {tls_confirmed}")

    services_index = {}
    for svc in all_services:
        sname = svc["service"]
        if sname not in services_index:
            services_index[sname] = []
        services_index[sname].append(f"{svc['host']}:{svc['port']}")

    parsed_data = {
        "scan_dir": scan_dir,
        "parsed_at": datetime.now().isoformat(),
        "host_count": len(hosts),
        "service_count": len(all_services),
        "tls_count": tls_confirmed,
        "hosts": hosts,
        "services_index": services_index,
    }

    output_path = output or "parsed.json"
    with open(output_path, "w") as f:
        json.dump(parsed_data, f, indent=2)
    print(f"[+] Wrote: {output_path}")

    _generate_cmds(all_services, services_index)
    _print_summary(parsed_data)

    return parsed_data


def _generate_cmds(services, services_index):
    tool_files = {}

    for tool_name, cfg in TOOL_CMDS.items():
        lines = []
        seen = set()

        outdir = f"run-output/{tool_name}"

        if cfg.get("match_all_tls"):
            for svc in services:
                if not svc.get("tls"):
                    continue
                key = f"{svc['host']}:{svc['port']}"
                if key in seen:
                    continue
                seen.add(key)
                if svc.get("tls") and "cmd_tls" in cfg:
                    cmd = cfg["cmd_tls"].format(host=svc["host"], port=svc["port"], outdir=outdir)
                else:
                    cmd = cfg["cmd"].format(host=svc["host"], port=svc["port"], outdir=outdir)
                lines.append(cmd)
        else:
            for svc_name in cfg["services"]:
                if svc_name not in services_index:
                    continue
                for entry in services_index[svc_name]:
                    if entry in seen:
                        continue
                    seen.add(entry)
                    host, port_str = entry.rsplit(":", 1)
                    port = int(port_str)

                    svc = next(
                        (s for s in services if s["host"] == host and s["port"] == port),
                        None
                    )
                    if svc is None:
                        continue

                    if cfg.get("needs_tls") and not svc.get("tls"):
                        continue

                    if svc.get("tls") and "cmd_tls" in cfg:
                        cmd = cfg["cmd_tls"].format(host=host, port=port, outdir=outdir)
                    else:
                        cmd = cfg["cmd"].format(host=host, port=port, outdir=outdir)
                    lines.append(cmd)

        if lines:
            cmds_file = f"{tool_name}.cmds"
            with open(cmds_file, "w") as f:
                for line in lines:
                    f.write(line + "\n")
            print(f"[+] Wrote {len(lines)} commands: {cmds_file}")
            tool_files[tool_name] = cmds_file

    _generate_main_sh(tool_files)


def _generate_main_sh(tool_files):
    path = "main.sh"
    with open(path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write(f"# Generated by lsec parse on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# Usage: bash main.sh [parallel_jobs]\n")
        f.write("#        bash main.sh 8\n\n")
        f.write('JOBS=${1:-4}\n\n')
        f.write('run_cmds() {\n')
        f.write('    local file=$1\n')
        f.write('    local label=$2\n')
        f.write('    if [ -s "$file" ]; then\n')
        f.write('        echo "[*] Running $label... ($(wc -l < "$file") targets)"\n')
        f.write('        parallel -j "$JOBS" < "$file"\n')
        f.write('        echo "[+] $label complete"\n')
        f.write('        echo\n')
        f.write('    fi\n')
        f.write('}\n\n')

        f.write('# Create output directories\n')
        for tool_name in sorted(tool_files, key=lambda t: (1 if t == "nikto" else 0, t)):
            f.write(f'mkdir -p run-output/{tool_name}\n')
        f.write('\n')

        for tool_name in sorted(tool_files, key=lambda t: (1 if t == "nikto" else 0, t)):
            f.write(f'run_cmds "{tool_name}.cmds" "{tool_name}"\n')

        f.write('\necho "[+] All tools complete"\n')

    os.chmod(path, 0o755)
    print(f"[+] Wrote: {path}")


def _print_summary(data):
    print()
    print("=" * 55)
    print("  Scan Summary")
    print("=" * 55)
    print(f"  Hosts up:        {data['host_count']}")
    print(f"  Open services:   {data['service_count']}")
    if data['tls_count']:
        print(f"  TLS enabled:     {data['tls_count']}")
    print()

    for sname, entries in sorted(data['services_index'].items()):
        print(f"  {sname:<20} {len(entries)}")

    print("=" * 55)
    print()

    print("  Services by host:")
    for host, info in sorted(data['hosts'].items()):
        ports = [
            f"{s['port']}/{s['protocol']}({s['service']})"
            for s in info["services"]
        ]
        print(f"    {host:<22} {', '.join(ports)}")
    print()
