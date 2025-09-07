"""
app.py - OSINT Recon Automation Toolkit (Flask backend)
Modified to minimize import dependencies and use subprocess calls

Features:
- /api/recon?target=example.com&use_spiderfoot=1 -> runs full recon including SpiderFoot
- /api/status/<job_id> -> get status (in-memory job store)
- Outputs saved under ./outputs/<target>/

Notes:
- Only run against targets you are authorized to test.
- Use a .env file to store API keys (RECON_ALLOWED_KEY, SHODAN_API_KEY, GITHUB_TOKEN, CENSYS_ID, CENSYS_SECRET)
"""
import sys
import os
import re
import json
import csv
import socket
import time
import threading
import traceback
import tempfile
import subprocess
from datetime import datetime, timezone
from queue import Queue

# Core Flask imports (required)
from flask import Flask, request, jsonify
from flask_cors import CORS

# Dynamic imports with fallbacks
def safe_import(module_name, package=None):
    """Safely import a module, return None if not available"""
    try:
        if package:
            return __import__(f"{package}.{module_name}", fromlist=[module_name])
        return __import__(module_name)
    except ImportError:
        return None

# Load modules dynamically
requests = safe_import('requests')
whois_module = safe_import('whois')
dns_resolver = None
try:
    dns_module = safe_import('dns.resolver')
    if dns_module:
        dns_resolver = dns_module
except:
    pass

builtwith = safe_import('builtwith')
shodan = safe_import('shodan')
sublist3r = safe_import('sublist3r')

# Load environment variables
dotenv = safe_import('dotenv')
if dotenv:
    try:
        dotenv.load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
    except Exception as e:
        print(f"Failed to load .env file: {e}")

# -------------------------
# Configuration
# -------------------------
OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

AUTHORIZATION_KEY = os.environ.get("RECON_ALLOWED_KEY")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
CENSYS_ID = os.environ.get("CENSYS_ID")
CENSYS_SECRET = os.environ.get("CENSYS_SECRET")
PORT = int(os.environ.get("PORT", 5000))

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389,
             443, 445, 465, 587, 636, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

DEFAULT_WORDS = ["www", "mail", "webmail", "smtp", "admin", "portal", "dev", "test",
                 "api", "beta", "shop", "m", "staging", "git", "docs"]

app = Flask(__name__)
CORS(app)

# -------------------------
# Utility functions
# -------------------------
def require_authorization(req):
    """Check if the request is authorized"""
    key = req.args.get("auth") or req.headers.get("X-RECON-AUTH")
    if not AUTHORIZATION_KEY:
        return False, "Server-side authorization key not configured."
    if key != AUTHORIZATION_KEY:
        return False, "Invalid or missing authorization key."
    return True, None

def save_output(target, data):
    """Save recon results to JSON and CSV files"""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    outdir = os.path.join(OUTPUT_DIR, safe)
    os.makedirs(outdir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    
    # Save JSON
    json_path = os.path.join(outdir, f"recon_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

    # Save summary CSV
    csv_path = os.path.join(outdir, f"summary_{timestamp}.csv")
    with open(csv_path, "w", newline="") as csvf:
        writer = csv.writer(csvf)
        writer.writerow(["hostname", "ip", "open_ports", "services"])
        for h in data.get("hosts", []):
            writer.writerow([
                h.get("hostname"), ",".join(h.get("ips", [])), ",".join(str(p) for p in h.get("open_ports", [])),
                ";".join(h.get("services", []))
            ])

    # Save CVE CSV
    cve_csv_path = os.path.join(outdir, f"cve_{timestamp}.csv")
    with open(cve_csv_path, "w", newline="") as csvf:
        writer = csv.writer(csvf)
        writer.writerow(["software", "cve_id", "cvss", "summary", "references"])
        for software, cves in data.get("cves", {}).items():
            for cve in cves:
                writer.writerow([
                    software,
                    cve.get("id", "N/A"),
                    cve.get("cvss", "N/A"),
                    cve.get("summary", "")[:200],
                    ";".join(cve.get("references", []))
                ])

    return json_path, csv_path, cve_csv_path

def normalized_domain(target):
    """Normalize and validate domain input"""
    if not target or not isinstance(target, str):
        return None
    t = target.strip().lower()
    t = re.sub(r"^https?://", "", t)
    t = t.split("/")[0]
    # Validate domain format
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]{1,253}[a-zA-Z0-9]$', t):
        return None
    return t

def dns_resolve(hostname, timeout=2.0):
    """Resolve DNS with multiple fallbacks"""
    ips = set()
    print(f"Resolving DNS for {hostname}")

    # Try dns.resolver
    if dns_resolver:
        try:
            resolver = dns_resolver.Resolver()
            resolver.lifetime = timeout
            try:
                answers = resolver.resolve(hostname, "A")
                for r in answers:
                    ip = r.to_text()
                    ips.add(ip)
                    print(f"Resolved A record: {ip}")
            except:
                pass
            try:
                answers = resolver.resolve(hostname, "AAAA")
                for r in answers:
                    ip = r.to_text()
                    ips.add(ip)
                    print(f"Resolved AAAA record: {ip}")
            except:
                pass
        except Exception as e:
            print(f"DNS resolver failed for {hostname}: {str(e)}")

    # Fallback to dig
    if not ips:
        try:
            result = subprocess.run(['dig', '+short', hostname, 'A'], capture_output=True, text=True, timeout=timeout)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and line.count('.') == 3 and not line.startswith(';'):
                        ips.add(line)
                        print(f"Resolved A record via dig: {line}")
                result_aaaa = subprocess.run(['dig', '+short', hostname, 'AAAA'], capture_output=True, text=True, timeout=timeout)
                if result_aaaa.returncode == 0:
                    lines = result_aaaa.stdout.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and ':' in line and not line.startswith(';'):
                            ips.add(line)
                            print(f"Resolved AAAA record via dig: {line}")
        except FileNotFoundError:
            print(f"dig command not found for {hostname}")
        except subprocess.TimeoutExpired:
            print(f"dig timed out for {hostname}")
        except Exception as e:
            print(f"dig subprocess failed for {hostname}: {str(e)}")

    # Fallback to socket
    if not ips:
        try:
            ip = socket.gethostbyname(hostname)
            ips.add(ip)
            print(f"Resolved via socket: {ip}")
        except Exception as e:
            print(f"Socket resolution failed for {hostname}: {str(e)}")

    if not ips:
        print(f"No IPs resolved for {hostname}")
    return list(ips)

def whois_lookup(domain):
    """Perform WHOIS lookup with python-whois or subprocess"""
    if whois_module:
        try:
            w = whois_module.whois(domain)
            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "whois": str(w),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": w.emails,
                "nets": w.nets if hasattr(w, 'nets') else None,
                "cidr": w.cidr if hasattr(w, 'cidr') else None,
                "source": "python-whois"
            }
        except Exception as e:
            print(f"WHOIS lookup failed for {domain}: {str(e)}")
    
    # Fallback to subprocess whois
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            return {"whois": result.stdout, "source": "subprocess"}
    except FileNotFoundError:
        print(f"whois command not found for {domain}")
    except subprocess.TimeoutExpired:
        print(f"whois subprocess timed out for {domain}")
    except Exception as e:
        print(f"whois subprocess failed for {domain}: {str(e)}")
    
    return {"error": "WHOIS not available"}

def crt_sh_subdomains(domain):
    """Query crt.sh for subdomains"""
    if not requests:
        return []
    
    found = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        print(f"Querying crt.sh for {domain}")
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            try:
                arr = r.json()
                for entry in arr:
                    name = entry.get("name_value")
                    if not name:
                        continue
                    for n in str(name).splitlines():
                        if n.endswith(domain):
                            found.add(n.lower())
            except ValueError:
                txt = r.text
                for match in re.findall(r'>([\w\-\._]+\.' + re.escape(domain) + r')<', txt):
                    found.add(match.lower())
        else:
            print(f"crt.sh request failed for {domain}: status {r.status_code}")
    except Exception as e:
        print(f"crt.sh error for {domain}: {str(e)}")
    return sorted(found)

def dns_bruteforce(domain, wordlist=None, threads=10):
    """Perform DNS brute-forcing with thread-safe set"""
    if wordlist is None:
        wordlist = DEFAULT_WORDS
    found = set()
    
    def worker(host):
        ips = dns_resolve(host)
        if ips:
            found.add((host, ips))

    threads_list = []
    for w in wordlist:
        host = f"{w}.{domain}"
        t = threading.Thread(target=worker, args=(host,))
        t.daemon = True
        t.start()
        threads_list.append(t)
        if len(threads_list) >= threads:
            for t in threads_list:
                t.join()
            threads_list = []

    for t in threads_list:
        t.join()

    return sorted([(host, ips) for host, ips in found], key=lambda x: x[0])

def simple_port_scan(ip, ports=None, timeout=1.5):
    """Perform simple port scanning with sockets"""
    if ports is None:
        ports = TOP_PORTS
    open_ports = []
    services = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result = s.connect_ex((ip, p))
            if result == 0:
                try:
                    s.settimeout(0.5)
                    s.sendall(b"\r\n")
                    banner = s.recv(512)
                    banner_text = banner.decode(errors="ignore").strip()
                except Exception:
                    banner_text = ""
                open_ports.append(p)
                services.append({"port": p, "banner": banner_text})
        except Exception as e:
            print(f"Socket error for {ip}:{p}: {str(e)}")
        finally:
            try:
                s.close()
            except Exception:
                pass
    return open_ports, services

def detect_techstack_from_url(url):
    """Detect tech stack using builtwith or HTTP headers"""
    tech = {}
    if builtwith:
        try:
            tech = builtwith.parse(url)
            return tech
        except Exception as e:
            print(f"Builtwith failed for {url}: {str(e)}")
    
    if requests:
        try:
            r = requests.get(url, timeout=5)
            tech = {"headers_guess": dict(r.headers)}
        except Exception as e:
            print(f"Tech stack detection failed for {url}: {str(e)}")
            tech = {"error": str(e)}
    else:
        tech = {"error": "requests module not available"}
    return tech

def github_search_code(domain, token=None, max_results=30):
    """Search GitHub for code leaks"""
    if not requests:
        return []
    
    results = []
    headers = {"User-Agent": "ReconToolkit/1.0"}
    if token:
        headers["Authorization"] = f"token {token}"
        try:
            q = f'"{domain}" in:file'
            url = "https://api.github.com/search/code"
            params = {"q": q, "per_page": max_results}
            print(f"Querying GitHub for {domain}")
            r = requests.get(url, headers=headers, params=params, timeout=8)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("items", [])[:max_results]:
                    results.append({
                        "path": item.get("path"),
                        "repository": item.get("repository", {}).get("full_name"),
                        "url": item.get("html_url")
                    })
                return results
        except Exception as e:
            print(f"GitHub search error for {domain}: {str(e)}")
    
    # Fallback web search
    try:
        q = f'{domain} "password" OR "secret" OR "api_key" OR "aws_secret"'
        url = f"https://github.com/search?q={requests.utils.quote(q)}&type=code"
        print(f"Querying GitHub fallback for {domain}")
        r = requests.get(url, headers=headers, timeout=8)
        if r.status_code == 200:
            html = r.text
            for match in re.findall(r'href="(/[^/]+/[^/]+/blob/[^"]+)"', html)[:max_results]:
                results.append({"url": "https://github.com" + match})
    except Exception as e:
        print(f"GitHub fallback search error for {domain}: {str(e)}")
    return results

def pastebin_search(domain, max_results=10):
    """Search Pastebin for leaks"""
    if not requests:
        return []
    
    finds = []
    try:
        url = f"https://pastebin.com/search?q={requests.utils.quote(domain)}"
        print(f"Querying Pastebin for {domain}")
        r = requests.get(url, timeout=6, headers={"User-Agent": "ReconToolkit/1.0"})
        if r.status_code == 200:
            html = r.text
            for m in re.findall(r'href="/([A-Za-z0-9]{8})"', html):
                finds.append("https://pastebin.com/raw/" + m)
                if len(finds) >= max_results:
                    break
    except Exception as e:
        print(f"Pastebin search error for {domain}: {str(e)}")
    
    results = []
    for u in finds:
        try:
            print(f"Fetching Pastebin content from {u}")
            r = requests.get(u, timeout=5)
            if r.status_code == 200 and domain in r.text:
                results.append({"url": u, "snippet": r.text[:500]})
        except Exception as e:
            print(f"Pastebin content fetch error for {u}: {str(e)}")
    return results

def try_s3_bucket_guess(domain):
    """Guess and check S3 bucket accessibility"""
    if not requests:
        return []
    
    candidates = [
        domain, domain.replace(".", "-"), f"www-{domain}", f"{domain}-assets", f"assets-{domain}"
    ]
    found = []
    headers = {"User-Agent": "ReconToolkit/1.0"}
    for c in candidates:
        urls = [f"https://{c}.s3.amazonaws.com", f"https://s3.amazonaws.com/{c}"]
        for u in urls:
            try:
                print(f"Checking S3 bucket at {u}")
                r = requests.get(u, timeout=5, headers=headers, allow_redirects=True)
                if r.status_code in (200, 403):
                    found.append({"bucket": c, "url": u, "status": r.status_code})
            except Exception as e:
                print(f"S3 bucket check error for {u}: {str(e)}")
    return found

def cve_search(query_software):
    """Search CVEs for a given software"""
    if not requests:
        return []
    
    out = []
    try:
        url = f"https://cve.circl.lu/api/search/{requests.utils.quote(query_software)}"
        print(f"Querying CVE for {query_software}")
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            data = r.json()
            for c in data.get("results", [])[:20]:
                out.append({
                    "id": c.get("id"),
                    "summary": c.get("summary"),
                    "cvss": c.get("cvss"),
                    "references": c.get("references"),
                    "source": "cve.circl.lu"
                })
    except Exception as e:
        print(f"CVE search error for {query_software}: {str(e)}")
    return out

def shodan_lookup_ip(ip):
    """Lookup IP in Shodan"""
    if not SHODAN_API_KEY or not shodan:
        return {"error": "Shodan not configured or library missing"}
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        print(f"Querying Shodan for {ip}")
        res = api.host(ip)
        # Add CVEs from Shodan if available
        if "vulns" in res:
            cves = []
            for cve_id in res.get("vulns", []):
                cves.append({
                    "id": cve_id,
                    "summary": f"Detected by Shodan for {ip}",
                    "cvss": None,
                    "references": [],
                    "source": "shodan",
                    "ip": ip
                })
            res["detected_cves"] = cves
        return res
    except Exception as e:
        print(f"Shodan lookup error for {ip}: {str(e)}")
        return {"error": str(e)}

def run_harvester_subprocess(domain, limit=200):
    """Run theHarvester via subprocess"""
    emails = set()
    hostnames = set()
    
    commands = [
        ["python3", "-m", "theHarvester", "-d", domain, "-l", str(limit), "-b", "bing"],
        ["python3", "-m", "theHarvester", "-d", domain, "-l", str(limit), "-b", "yahoo"],
        ["python3", "-m", "theHarvester", "-d", domain, "-l", str(limit), "-b", "duckduckgo"],
        ["theHarvester", "-d", domain, "-l", str(limit), "-b", "bing"],
        ["theHarvester", "-d", domain, "-l", str(limit), "-b", "yahoo"]
    ]
    
    for cmd in commands:
        try:
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=100)
            if result.returncode == 0:
                output = result.stdout
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                found_emails = re.findall(email_pattern, output)
                emails.update(found_emails)
                
                lines = output.split('\n')
                for line in lines:
                    if domain in line and '.' in line:
                        words = line.split()
                        for word in words:
                            if word.endswith(domain) and word.count('.') >= 1:
                                hostnames.add(word.strip('.,;:'))
                break
        except FileNotFoundError:
            print(f"theHarvester command not found: {' '.join(cmd)}")
        except subprocess.TimeoutExpired:
            print(f"theHarvester timed out: {' '.join(cmd)}")
        except Exception as e:
            print(f"theHarvester error: {e}")
            continue
    
    return {"emails": list(emails), "hosts": list(hostnames)}

def get_typosquats_subprocess(domain):
    """Run dnstwist via subprocess"""
    try:
        print(f"Running dnstwist subprocess for {domain}")
        result = subprocess.run(['dnstwist', '--format', 'json', domain], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            registered = [d['domain'] for d in data[1:] if d.get('dns_a') or d.get('dns_aaaa')]
            return registered
    except FileNotFoundError:
        print(f"dnstwist command not found for {domain}")
    except subprocess.TimeoutExpired:
        print(f"dnstwist timed out for {domain}")
    except Exception as e:
        print(f"dnstwist subprocess error for {domain}: {str(e)}")
    return []

def get_mx_records(domain):
    """Get MX records for the domain"""
    mx = []
    if dns_resolver:
        try:
            resolver = dns_resolver.Resolver()
            print(f"Querying MX records for {domain}")
            answers = resolver.resolve(domain, 'MX')
            for r in answers:
                mx.append(str(r.exchange).rstrip('.'))
        except Exception as e:
            print(f"MX record lookup failed for {domain}: {str(e)}")
    else:
        try:
            result = subprocess.run(['dig', '+short', domain, 'MX'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    parts = line.strip().split()
                    if parts and len(parts) > 1:
                        mx_record = parts[1].rstrip('.')
                        if mx_record:
                            mx.append(mx_record)
        except FileNotFoundError:
            print(f"dig command not found for MX lookup: {domain}")
        except subprocess.TimeoutExpired:
            print(f"dig timed out for MX lookup: {domain}")
        except Exception as e:
            print(f"MX subprocess failed for {domain}: {e}")
    return mx

def run_sublist3r_subprocess(domain):
    """Run Sublist3r via subprocess"""
    subdomains = []
    commands = [
        ["python3", "-m", "sublist3r", "-d", domain, "-v"],
        ["sublist3r", "-d", domain, "-v"],
        ["python", "-m", "sublist3r", "-d", domain, "-v"]
    ]
    
    for cmd in commands:
        try:
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=100)
            if result.returncode == 0:
                output_lines = result.stdout.split('\n')
                for line in output_lines:
                    line = line.strip()
                    if line.endswith(domain) and line not in subdomains:
                        subdomains.append(line)
                break
        except FileNotFoundError:
            print(f"Sublist3r command not found: {' '.join(cmd)}")
        except subprocess.TimeoutExpired:
            print(f"Sublist3r timed out: {' '.join(cmd)}")
        except Exception as e:
            print(f"Sublist3r error: {e}")
            continue
    
    return subdomains

def run_spiderfoot_subprocess(domain, output_dir):
    """Run SpiderFoot via subprocess"""
    try:
        spiderfoot_commands = [
            ["python3", "sf.py", "-t", domain, "-m", "sfp_dnsresolve,sfp_crt,sfp_builtwith", "-s", domain],
            ["python", "sf.py", "-t", domain, "-m", "sfp_dnsresolve,sfp_crt,sfp_builtwith", "-s", domain]
        ]
        
        for cmd in spiderfoot_commands:
            try:
                print(f"Running SpiderFoot: {' '.join(cmd)}")
                result = subprocess.run(cmd, cwd=output_dir, capture_output=True, text=True, timeout=200)
                if result.returncode == 0:
                    return {"status": "success", "output": result.stdout[:1000]}
                break
            except FileNotFoundError:
                print(f"SpiderFoot command not found: {' '.join(cmd)}")
            except subprocess.TimeoutExpired:
                print(f"SpiderFoot timed out: {' '.join(cmd)}")
        
        return {"status": "failed", "error": "SpiderFoot not available or failed"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def run_nmap_subprocess(target, ports=None):
    """Run nmap via subprocess as alternative to socket scanning"""
    if ports is None:
        ports = TOP_PORTS
    
    try:
        port_range = ",".join(map(str, ports))
        cmd = ["nmap", "-sS", "-p", port_range, target]
        print(f"Running nmap: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=50)
        
        if result.returncode == 0:
            open_ports = []
            lines = result.stdout.split('\n')
            for line in lines:
                if '/tcp' in line and 'open' in line:
                    port = int(line.split('/')[0])
                    open_ports.append(port)
            return open_ports
    except FileNotFoundError:
        print(f"nmap command not found for {target}")
    except subprocess.TimeoutExpired:
        print(f"nmap timed out for {target}")
    except Exception as e:
        print(f"nmap error: {e}")
    
    return []

def run_amass_subprocess(domain):
    """Run Amass via subprocess for subdomain enumeration"""
    subdomains = []
    try:
        cmd = ["amass", "enum", "-d", domain]
        print(f"Running amass: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            subdomains = [line.strip() for line in lines if line.strip().endswith(domain)]
    except FileNotFoundError:
        print(f"amass command not found for {domain}")
    except subprocess.TimeoutExpired:
        print(f"amass timed out for {domain}")
    except Exception as e:
        print(f"amass error: {e}")
    
    return subdomains

def run_gobuster_subprocess(domain, wordlist_path=None):
    """Run Gobuster via subprocess for directory enumeration"""
    if not wordlist_path:
        return []
    
    directories = []
    try:
        cmd = ["gobuster", "dir", "-u", f"https://{domain}", "-w", wordlist_path, "-q"]
        print(f"Running gobuster: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=100)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if line.startswith('/'):
                    directories.append(line.strip())
    except FileNotFoundError:
        print(f"gobuster command not found for {domain}")
    except subprocess.TimeoutExpired:
        print(f"gobuster timed out for {domain}")
    except Exception as e:
        print(f"gobuster error: {e}")
    
    return directories

def check_ssl_certificate(domain):
    """Check SSL certificate information using openssl subprocess"""
    cert_info = {}
    try:
        cmd = ["openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain]
        result = subprocess.run(cmd, input="\n", capture_output=True, text=True, timeout=8)
        
        if result.returncode == 0:
            output = result.stdout
            if "subject=" in output:
                subject_line = [line for line in output.split('\n') if line.strip().startswith('subject=')]
                if subject_line:
                    cert_info['subject'] = subject_line[0].replace('subject=', '').strip()
            
            if "issuer=" in output:
                issuer_line = [line for line in output.split('\n') if line.strip().startswith('issuer=')]
                if issuer_line:
                    cert_info['issuer'] = issuer_line[0].replace('issuer=', '').strip()
    except FileNotFoundError:
        print(f"openssl command not found for {domain}")
    except subprocess.TimeoutExpired:
        print(f"openssl timed out for {domain}")
    except Exception as e:
        print(f"SSL check error: {e}")
        cert_info['error'] = str(e)
    
    return cert_info

# -------------------------
# Recon worker
# -------------------------
def run_recon(target, options=None):
    """Base recon function"""
    domain = normalized_domain(target)
    if not domain:
        raise ValueError("Invalid or empty domain")
    
    print(f"Starting recon for {domain}")
    result = {
        "target": domain,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "subdomains": [],
        "hosts": [],
        "whois": {},
        "tech": {},
        "github_hits": [],
        "paste_hits": [],
        "s3_buckets": [],
        "cves": {},
        "shodan": {},
        "censys": [],
        "harvester": {},
        "ip_ranges": [],
        "phishing_vectors": {"mx_servers": [], "typosquat_domains": []},
        "spiderfoot_events": []
    }

    # WHOIS
    result["whois"] = whois_lookup(domain)

    # IP ranges from WHOIS
    w = result["whois"]
    if isinstance(w.get("nets"), list) and w["nets"]:
        result["ip_ranges"] = [net.get("cidr") for net in w["nets"] if net.get("cidr")]
    elif w.get("cidr"):
        result["ip_ranges"] = [w["cidr"]]

    # Subdomains
    wl = options.get("wordlist") if options else DEFAULT_WORDS
    if isinstance(wl, str) and os.path.exists(wl):
        with open(wl, "r") as f:
            wl = [l.strip() for l in f if l.strip()]
    elif not isinstance(wl, list):
        wl = DEFAULT_WORDS

    # 1. Sublist3r subprocess
    try:
        sublist3r_subs = run_sublist3r_subprocess(domain)
        result["subdomains"].extend(sublist3r_subs)
    except Exception as e:
        print(f"Sublist3r subprocess error: {e}")

    # 2. CRT.sh lookup
    try:
        crt_subs = crt_sh_subdomains(domain)
        for sub in crt_subs:
            if sub not in result["subdomains"]:
                result["subdomains"].append(sub)
    except Exception as e:
        print(f"CRT.sh error: {e}")

    # 3. DNS brute-force
    try:
        for host, _ in dns_bruteforce(domain, wordlist=wl, threads=20):
            if host not in result["subdomains"]:
                result["subdomains"].append(host)
    except Exception as e:
        print(f"DNS brute-force error: {e}")

    # 4. theHarvester subprocess
    try:
        result["harvester"] = run_harvester_subprocess(domain)
        if "hosts" in result["harvester"]:
            for h in result["harvester"]["hosts"]:
                if h.endswith(domain) and h not in result["subdomains"]:
                    result["subdomains"].append(h)
    except Exception as e:
        print(f"theHarvester error: {e}")
        result["harvester"] = {"error": str(e)}

    # Fallback if no subdomains found
    if not result["subdomains"]:
        result["subdomains"].extend(crt_sh_subdomains(domain))
        result["subdomains"].extend([h for h, _ in dns_bruteforce(domain, wordlist=wl)])

    # Resolve subdomains & scan
    hosts_map = {}
    subdomains = set(result["subdomains"])
    subdomains.add(domain)
    for sub in subdomains:
        ips = dns_resolve(sub)
        hosts_map[sub] = {"hostname": sub, "ips": ips, "open_ports": [], "services": []}

    for host, data in hosts_map.items():
        for ip in data["ips"]:
            print(f"Scanning ports for {ip}")
            open_ports, services = simple_port_scan(ip, ports=TOP_PORTS)
            data["open_ports"].extend(open_ports)
            data["open_ports"] = list(set(data["open_ports"]))
            data["services"].extend([f"{s['port']}:{s['banner']}" for s in services])

    result["hosts"] = list(hosts_map.values())

    # Tech stack
    try:
        result["tech"] = detect_techstack_from_url(f"https://{domain}")
    except Exception:
        try:
            result["tech"] = detect_techstack_from_url(f"http://{domain}")
        except Exception:
            result["tech"] = {}

    # Public sources
    result["github_hits"] = github_search_code(domain, token=GITHUB_TOKEN)
    result["paste_hits"] = pastebin_search(domain)
    result["s3_buckets"] = try_s3_bucket_guess(domain)

    # CVEs
    software_names = list(result["tech"].keys())
    for s in software_names[:8]:
        cves = cve_search(s)
        if cves:
            result["cves"][s] = cves

    # Shodan with CVEs
    if SHODAN_API_KEY and shodan:
        ips = set(ip for h in result["hosts"] for ip in h.get("ips", []))
        for ip in list(ips)[:15]:
            shodan_data = shodan_lookup_ip(ip)
            result["shodan"][ip] = shodan_data
            if "detected_cves" in shodan_data:
                result["cves"]["shodan_detected"] = shodan_data["detected_cves"]

    # Phishing vectors
    result["phishing_vectors"]["mx_servers"] = get_mx_records(domain)
    result["phishing_vectors"]["typosquat_domains"] = get_typosquats_subprocess(domain)

    # SpiderFoot Integration
    if options and options.get("use_spiderfoot"):
        try:
            safe_domain = re.sub(r"[^A-Za-z0-9_.-]", "_", domain)
            sf_output_dir = os.path.join(OUTPUT_DIR, safe_domain)
            os.makedirs(sf_output_dir, exist_ok=True)
            spiderfoot_result = run_spiderfoot_subprocess(domain, sf_output_dir)
            result["spiderfoot_events"].append(spiderfoot_result)
        except Exception as e:
            result["spiderfoot_events"].append({"error": str(e)})

    return result

def enhanced_run_recon(target, options=None):
    """Enhanced recon function with additional tools"""
    result = run_recon(target, options)
    
    domain = normalized_domain(target)
    if not domain:
        raise ValueError("Invalid or empty domain")
    
    try:
        # SSL Certificate check
        result['ssl_info'] = check_ssl_certificate(domain)
        
        # Amass for additional subdomain enumeration
        amass_subs = run_amass_subprocess(domain)
        if amass_subs:
            result['amass_subdomains'] = amass_subs
            for sub in amass_subs:
                if sub not in result['subdomains']:
                    result['subdomains'].append(sub)
        
        # Enhanced port scanning with nmap
        for host_info in result['hosts']:
            for ip in host_info['ips']:
                nmap_ports = run_nmap_subprocess(ip)
                if nmap_ports:
                    host_info['nmap_ports'] = nmap_ports
                    all_ports = set(host_info['open_ports'] + nmap_ports)
                    host_info['open_ports'] = sorted(list(all_ports))
        
        # Update summary
        spiderfoot_status = "not_run"
        if result["spiderfoot_events"] and isinstance(result["spiderfoot_events"], list) and result["spiderfoot_events"]:
            first_event = result["spiderfoot_events"][0]
            if isinstance(first_event, dict):
                spiderfoot_status = first_event.get("status", "error")
        
        result["summary"] = {
            "num_subdomains": len(result["subdomains"]),
            "num_hosts": len(result["hosts"]),
            "num_emails": len(result["harvester"].get("emails", [])),
            "github_hits": len(result["github_hits"]),
            "paste_hits": len(result["paste_hits"]),
            "spiderfoot_status": spiderfoot_status
        }
        
        # Save output
        json_path, csv_path, cve_csv_path = save_output(domain, result)
        result["output_files"] = {"json": json_path, "csv": csv_path, "cve_csv": cve_csv_path}
        
    except Exception as e:
        print(f"Enhanced recon features error: {e}")
        result['enhanced_features_error'] = str(e)
    
    return result

# -------------------------
# Flask endpoints
# -------------------------
JOBS = {}

@app.route("/api/recon", methods=["GET"])
def api_recon():
    """Run reconnaissance for a target domain"""
    ok, msg = require_authorization(request)
    if not ok:
        return jsonify({"error": msg}), 403

    target = request.args.get("target")
    if not target:
        return jsonify({"error": "Missing required parameter: target"}), 400

    domain = normalized_domain(target)
    if not domain:
        return jsonify({"error": "Invalid domain format"}), 400

    wordlist = request.args.get("wordlist")
    use_sf = request.args.get("use_spiderfoot") == "1"
    options = {}
    if wordlist:
        options["wordlist"] = wordlist
    options["use_spiderfoot"] = use_sf

    job_id = f"{int(time.time())}-{re.sub(r'[^0-9A-Za-z]', '', domain)[:20]}"
    JOBS[job_id] = {"status": "running", "target": domain, "started": datetime.now(timezone.utc).isoformat()}

    try:
        res = enhanced_run_recon(domain, options=options)
        JOBS[job_id].update({"status": "finished", "finished": datetime.now(timezone.utc).isoformat(), "result": res})
        return jsonify({"job_id": job_id, "result": res})
    except Exception as e:
        JOBS[job_id].update({"status": "error", "error": str(e)})
        print(f"Recon error for {domain}: {str(e)}")
        traceback.print_exc()
        return jsonify({"job_id": job_id, "error": str(e)}), 500

@app.route("/api/status/<job_id>", methods=["GET"])
def api_status(job_id):
    """Check status of a recon job"""
    ok, msg = require_authorization(request)
    if not ok:
        return jsonify({"error": msg}), 403
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "unknown job id"}), 404
    return jsonify(job)

@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check endpoint"""
    status = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dependencies": {
            "requests": requests is not None,
            "whois": whois_module is not None,
            "dns_resolver": dns_resolver is not None,
            "builtwith": builtwith is not None,
            "shodan": shodan is not None,
            "sublist3r": sublist3r is not None
        },
        "config": {
            "shodan_configured": bool(SHODAN_API_KEY),
            "github_configured": bool(GITHUB_TOKEN),
            "censys_configured": bool(CENSYS_ID and CENSYS_SECRET),
            "auth_configured": bool(AUTHORIZATION_KEY)
        },
        "tools_status": {
            "subprocess_available": True,
            "socket_available": True,
            "dns_fallback": True,
            "whois_fallback": True
        }
    }
    return jsonify(status)

@app.route("/api/tools/test", methods=["GET"])
def api_test_tools():
    """Test individual tools availability"""
    ok, msg = require_authorization(request)
    if not ok:
        return jsonify({"error": msg}), 403
    
    test_results = {}
    
    # Test subprocess tools
    subprocess_tools = ["whois", "dnstwist", "sublist3r", "theHarvester", "dig", "nmap", "amass", "openssl"]
    for tool in subprocess_tools:
        try:
            result = subprocess.run([tool, "--help"], capture_output=True, timeout=5)
            test_results[tool] = {"available": result.returncode == 0, "method": "subprocess"}
        except FileNotFoundError:
            test_results[tool] = {"available": False, "method": "subprocess", "error": "Command not found"}
        except subprocess.TimeoutExpired:
            test_results[tool] = {"available": False, "method": "subprocess", "error": "Timed out"}
        except Exception as e:
            test_results[tool] = {"available": False, "method": "subprocess", "error": str(e)}
    
    # Test Python modules
    python_modules = {
        "requests": requests,
        "whois": whois_module,
        "dns.resolver": dns_resolver,
        "builtwith": builtwith,
        "shodan": shodan,
        "sublist3r": sublist3r
    }
    
    for module_name, module_obj in python_modules.items():
        test_results[f"python_{module_name}"] = {
            "available": module_obj is not None,
            "method": "python_import"
        }
    
    return jsonify({"test_results": test_results})

@app.route("/")
def index():
    """Root endpoint with usage information"""
    return (
        "<h3>Recon Toolkit Backend (Subprocess-Enhanced)</h3>"
        "<p>Use <code>/api/recon?target=example.com&auth=YOUR_KEY&use_spiderfoot=1</code> to start recon.</p>"
        "<p>Check <code>/api/health</code> for dependency status.</p>"
        "<p>Check <code>/api/tools/test?auth=KEY</code> for individual tool testing.</p>"
        "<p><strong>Warning:</strong> Only use against authorized targets.</p>"
        "<h4>Available Endpoints:</h4>"
        "<ul>"
        "<li><code>GET /api/recon?target=DOMAIN&auth=KEY</code> - Start reconnaissance</li>"
        "<li><code>GET /api/status/JOB_ID?auth=KEY</code> - Check job status</li>"
        "<li><code>GET /api/health</code> - Check system health</li>"
        "<li><code>GET /api/tools/test?auth=KEY</code> - Test individual tools</li>"
        "</ul>"
        "<h4>Features:</h4>"
        "<ul>"
        "<li>Minimal import dependencies</li>"
        "<li>Subprocess fallbacks for all tools</li>"
        "<li>Native socket-based port scanning</li>"
        "<li>DNS resolution with multiple fallbacks</li>"
        "<li>Amass and SSL certificate checks</li>"
        "<li>Works without Python security tool libraries</li>"
        "</ul>"
    )

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    print("🚀 Starting Recon Toolkit backend (Subprocess-Enhanced)")
    print(f"📁 Output directory: {OUTPUT_DIR}")
    print(f"🔑 Authorization required: {bool(AUTHORIZATION_KEY)}")
    print(f"🌐 Requests available: {requests is not None}")
    print(f"🔍 DNS resolver available: {dns_resolver is not None}")
    print(f"📊 Shodan configured: {bool(SHODAN_API_KEY)}")
    print(f"🐙 GitHub configured: {bool(GITHUB_TOKEN)}")
    print(f"🔍 Censys configured: {bool(CENSYS_ID and CENSYS_SECRET)}")
    print("🛠️ Using subprocess fallbacks for external tools")
    print("⚠️ This version minimizes import dependencies and relies on system tools")
    
    # Test critical system tools on startup
    critical_tools = ["ping"]
    for tool in critical_tools:
        try:
            subprocess.run([tool, "--help"], capture_output=True, timeout=2)
            print(f"✅ {tool} available")
        except Exception as e:
            print(f"❌ {tool} not available: {e}")
    
    app.run(host="0.0.0.0", port=PORT, debug=False)