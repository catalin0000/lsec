import os
import sys
import json
import ssl
import socket
from datetime import datetime
from xml.etree import ElementTree
from concurrent.futures import ThreadPoolExecutor, as_completed


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

        os_info = ""
        os_el = host_elem.find("os")
        if os_el is not None:
            for osm in os_el.findall("osmatch"):
                os_info = osm.get("name", "") 

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
            probed = svc_el.get("methode", "") if svc_el is not None else ""
            confid = svc_el.get("conf", "") if svc_el is not None else ""
 
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
                "methode": probed,
                "conf": confid
            })
            # print(host,state, port_id, service, tunnel)

    # print(results)
    print("[*] Checking all ports if ssl...")
    result = check_ports_ssl(results)
    # print('this is the new list',result)
    print("[*] Checking all ports if web...")
    rslt =  check_is_web(result)
    # print('this is after web checks\n ------------------------------------\n', rslt)

    return rslt

def check_is_web_helper(item):
    from modules.me_http import is_web_service
    host = item['host']
    port = item['port']
    is_ssl = True if item['is_ssl'] else False
    rslt = is_web_service(host,port,is_ssl)
    if rslt:
        item['is_web'] = True
    else:
        item['is_web'] = False        
    return item

def check_is_web(results):
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(check_is_web_helper, item): item 
            for item in results
        }
        for future in as_completed(futures):
            future.result()
    return results

def check_ssl_helper(item):
    from modules.me_ssl import is_ssl
    host = item['host']
    port = item['port']
    rslt = is_ssl(host,port)
    if rslt:
        item['is_ssl'] = True
    else:
        item['is_ssl'] = False 
    return item
 
def check_ports_ssl(results):
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(check_ssl_helper, item): item 
            for item in results
        }
        for future in as_completed(futures):
            future.result()
    return results

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

    for xml_file in xml_files:
        xml_path = os.path.join(nmap_output_dir, xml_file)
        services = _parse_nmap_xml(xml_path)
