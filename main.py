#!/usr/bin/env python3
"""
AegisScan v3.0 — Professional Async Network Scanner
main.py — CLI entry point

Usage:
  python3 main.py --scan 192.168.1.1
  python3 main.py --scan 192.168.1.0/24 --ports top100 --timing aggressive
  python3 main.py --scan 192.168.1.1 --ports 1-1000 --timing t4
  python3 main.py --banner 192.168.1.1 --port 22
  python3 main.py --benchmark 192.168.1.1 --ports 1-1000
  python3 main.py --history 20
  python3 main.py --report 3 --format html
  python3 main.py --dashboard --host 127.0.0.1 --dash-port 5000
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

# Try uvloop for 2-4× speed on Linux/macOS
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

from core.port_parser import PortParser, PortParseError
from core.scanner_engine import ScanEngine, ScanStats, HostResult
from core.timing import get_timing
from core.os_detect import OSDetector
from core.service_fingerprint import ServiceFingerprinter
from core.web_recon import WebRecon, PortAnalyzer
from database.repository import Repository
from database.migrations import migrate
from utils.constants import ScanType
from utils.logger import get_logger

log = get_logger("aegisscan")

BANNER = r"""
  ╔═══════════════════════════════════════════════════╗
  ║  █████╗ ███████╗ ██████╗ ██╗███████╗███████╗      ║
  ║ ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝██╔════╝      ║
  ║ ███████║█████╗  ██║  ███╗██║███████╗███████╗       ║
  ║ ██╔══██║██╔══╝  ██║   ██║██║╚════██║╚════██║       ║
  ║ ██║  ██║███████╗╚██████╔╝██║███████║███████║       ║
  ║ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝╚══════╝      ║
  ║  Scan v3.0  ·  Async Engine  ·  nmap-services DB  ║
  ╚═══════════════════════════════════════════════════╝"""


def _load_config(path: str) -> dict:
    try:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except (ImportError, FileNotFoundError):
        return {}


# ─── Core scan runner ─────────────────────────────────────────────────────────

async def _run_scan(
    target: str,
    ports_spec: str,
    timing_name: str,
    repo: Repository,
    grab_banners: bool,
    quiet: bool,
) -> int:
    """Execute scan, persist results, return scan_id."""
    parser = PortParser()
    try:
        ports = parser.parse(ports_spec)
    except PortParseError as exc:
        log.error(f"Port parse error: {exc}")
        sys.exit(1)

    timing  = get_timing(timing_name)
    os_det  = OSDetector()
    svc_fp  = ServiceFingerprinter()

    log.info(f"Target   : {target}")
    log.info(f"Ports    : {len(ports)}  ({ports_spec})")
    log.info(f"Timing   : {timing.name}")
    log.info(f"Banners  : {'yes' if grab_banners else 'no'}")

    scan_type = ScanType.SUBNET if "/" in target else ScanType.TCP_CONNECT
    scan_id   = repo.create_scan(scan_type.value, target, ports_spec, timing_name)
    log.info(f"Scan ID  : {scan_id}")

    def cb(msg: str):
        if not quiet:
            log.info(msg)

    engine = ScanEngine(timing=timing, grab_banners=grab_banners, progress_cb=cb)
    t0 = time.monotonic()

    if "/" in target:
        results, stats = await engine.scan_subnet(target, ports)
    else:
        hr = await engine.scan_host(target, ports)
        results = [hr] if hr.is_alive else []
        stats = ScanStats(
            hosts_total=1, hosts_alive=len(results),
            ports_scanned=len(ports),
            ports_open=sum(len(r.open_ports) for r in results),
            elapsed_s=time.monotonic() - t0,
        )

    # Enrich with OS detection + service fingerprinting
    for r in results:
        banners     = {p.port: p.banner for p in r.open_ports if p.banner}
        open_ports  = [p.port for p in r.open_ports]
        os_guess    = os_det.detect(banners, open_ports)
        os_str      = os_det.format_guess(os_guess) if os_guess else None

        port_dicts = []
        for p in r.open_ports:
            svc_info = svc_fp.identify(p.port, p.banner, p.service)
            port_dicts.append({
                "port":        p.port,
                "state":       p.state.name.lower(),
                "service":     svc_info.name,
                "product":     svc_info.product,
                "version":     svc_info.version,
                "banner":      p.banner,
                "response_ms": p.response_ms,
            })

        repo.save_host(scan_id, r.ip, r.hostname, r.is_alive,
                       r.scan_ms, port_dicts, os_guess=os_str)

    repo.finish_scan(scan_id, stats.hosts_alive, stats.ports_open)

    # ── Output ────────────────────────────────────────────────────────────────
    rate = (stats.ports_scanned / stats.elapsed_s) if stats.elapsed_s > 0 else 0
    print(f"\n{'═'*60}")
    print(f"  SCAN #{scan_id} COMPLETE")
    print(f"{'─'*60}")
    print(f"  Hosts alive  : {stats.hosts_alive}/{stats.hosts_total}")
    print(f"  Open ports   : {stats.ports_open}")
    print(f"  Duration     : {stats.elapsed_s:.2f}s")
    print(f"  Rate         : {rate:.0f} ports/sec")
    print(f"{'═'*60}\n")

    for r in results:
        if not r.open_ports:
            continue
        banners    = {p.port: p.banner for p in r.open_ports if p.banner}
        open_ports = [p.port for p in r.open_ports]
        os_guess   = os_det.detect(banners, open_ports)
        os_str     = f"  OS: {os_det.format_guess(os_guess)}" if os_guess else ""

        print(f"  ┌─ {r.ip}  {r.hostname or ''}{os_str}")
        print(f"  │  {'PORT':<8} {'SERVICE':<20} {'VERSION':<22} {'RESP':>6}")
        print(f"  │  {'─'*58}")
        for p in r.open_ports:
            svc  = svc_fp.identify(p.port, p.banner, p.service)
            ver  = svc.version or ""
            prod = svc.product or svc.name
            ms   = f"{p.response_ms:.1f}ms"
            print(f"  │  {p.port:<8} {prod:<20} {ver:<22} {ms:>6}")
        print()

    print(f"  Tip: python3 main.py --report {scan_id} --format html")
    return scan_id


# ─── Benchmark ────────────────────────────────────────────────────────────────

async def _benchmark(target: str, ports_spec: str, timing_name: str) -> None:
    parser = PortParser()
    ports  = parser.parse(ports_spec)
    timing = get_timing(timing_name)
    engine = ScanEngine(timing=timing, grab_banners=False,
                        progress_cb=lambda _: None)

    print(f"\n  BENCHMARK MODE")
    print(f"  Target   : {target}")
    print(f"  Ports    : {len(ports)}")
    print(f"  Timing   : {timing.name}  (concurrency {timing.max_concurrent_hosts}h × {timing.max_concurrent_ports}p)")

    t0 = time.monotonic()
    if "/" in target:
        results, stats = await engine.scan_subnet(target, ports)
        n_hosts = stats.hosts_alive
        n_ports = stats.ports_scanned
        n_open  = stats.ports_open
    else:
        hr = await engine.scan_host(target, ports)
        results = [hr] if hr.is_alive else []
        n_hosts = len(results)
        n_ports = len(ports)
        n_open  = sum(len(r.open_ports) for r in results)

    elapsed = time.monotonic() - t0
    ops = n_ports * max(n_hosts, 1)

    print(f"\n  ┌─ RESULTS")
    print(f"  │  Elapsed      : {elapsed:.3f}s")
    print(f"  │  Port ops     : {ops}")
    print(f"  │  Rate         : {ops/elapsed:.0f} ops/sec")
    print(f"  │  Hosts alive  : {n_hosts}")
    print(f"  │  Open ports   : {n_open}")
    print(f"  └─ Timeout used : {timing.connection_timeout_ms}ms")


# ─── History ─────────────────────────────────────────────────────────────────

def show_history(repo: Repository, limit: int) -> None:
    scans = repo.list_scans(limit)
    if not scans:
        print("  No scan history. Run: python3 main.py --scan <target>")
        return
    w = {"id":5,"type":16,"target":24,"status":12,"hosts":7,"ports":7,"dur":9,"when":20}
    header = f"  {'ID':<{w['id']}} {'TYPE':<{w['type']}} {'TARGET':<{w['target']}} {'STATUS':<{w['status']}} {'HOSTS':<{w['hosts']}} {'PORTS':<{w['ports']}} {'DUR':<{w['dur']}} STARTED"
    print(f"\n{header}")
    print("  " + "─" * (sum(w.values()) + 10))
    for s in scans:
        dur = f"{s['duration_s']:.1f}s" if s.get("duration_s") else "—"
        print(f"  {s['id']:<{w['id']}} {s['scan_type']:<{w['type']}} {s['target']:<{w['target']}} "
              f"{s['status']:<{w['status']}} {s['hosts_found']:<{w['hosts']}} {s['ports_open']:<{w['ports']}} "
              f"{dur:<{w['dur']}} {(s.get('started_at') or '')[:19]}")


# ─── Report ──────────────────────────────────────────────────────────────────

def generate_report(repo: Repository, scan_id: int, fmt: str) -> None:
    data = repo.get_scan(scan_id)
    if not data:
        log.error(f"Scan {scan_id} not found"); return
    from reporting.report_generator import ReportGenerator
    gen  = ReportGenerator(output_dir="reports")
    path = gen.generate(data, fmt)
    if path:
        print(f"\n  ✓ Report saved: {path}")
    else:
        print(f"\n  ✗ Report generation failed")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_cli() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="aegisscan",
        description="AegisScan v3.0 — Professional Async Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Port specs:   80  |  80,443  |  1-1000  |  top100  |  - (all)
Timing:       paranoid t0  sneaky t1  polite t2
              normal t3   aggressive t4   insane t5

Examples:
  %(prog)s --scan 192.168.1.1
  %(prog)s --scan 192.168.1.0/24 --ports top100 --timing t4
  %(prog)s --scan 192.168.1.1 --ports 1-65535 --timing insane
  %(prog)s --banner 192.168.1.1 --port 22
  %(prog)s --benchmark 192.168.1.1 --ports 1-1000
  %(prog)s --report 1 --format html
  %(prog)s --dashboard --host 127.0.0.1
""",
    )
    g = ap.add_argument_group
    s = g("Scan")
    s.add_argument("--scan",       metavar="TARGET",  help="IP address or CIDR subnet")
    s.add_argument("--ports",      metavar="SPEC",    default="top100",
                   help="Port spec (default: top100)")
    s.add_argument("--timing",     metavar="PROFILE", default="normal",
                   choices=["paranoid","sneaky","polite","normal","aggressive","insane",
                            "t0","t1","t2","t3","t4","t5"])
    s.add_argument("--no-banner",  action="store_true", help="Skip banner grabbing")

    b = g("Banner / Single Port")
    b.add_argument("--banner",     metavar="TARGET",  help="Grab service banner")
    b.add_argument("--port",       metavar="PORT",    type=int, help="Port for --banner")

    rec = g("Web / Domain Recon")
    rec.add_argument("--recon",    metavar="TARGET",  help="Domain/IP recon (DNS, HTTP headers, tech stack)")
    rec.add_argument("--subdomains", action="store_true", help="Also check common subdomains (use with --recon)")
    rec.add_argument("--analyze",  metavar="SCAN_ID", type=int, help="Port dominance + OS distribution analysis from scan history")

    bm = g("Benchmark")
    bm.add_argument("--benchmark", metavar="TARGET",  help="Measure scan throughput")

    db = g("Database")
    db.add_argument("--history",   metavar="N",       nargs="?", const=20, type=int,
                    help="Show scan history (default: 20)")
    db.add_argument("--clear-db",  action="store_true", help="Delete all records")
    db.add_argument("--db-path",   default="aegisscan.db", metavar="FILE")

    r = g("Reports")
    r.add_argument("--report",     metavar="ID",      type=int, help="Generate report for scan ID")
    r.add_argument("--format",     choices=["json","html","pdf"], default="html")

    d = g("Dashboard")
    d.add_argument("--dashboard",  action="store_true", help="Start web dashboard")
    d.add_argument("--host",       default="127.0.0.1")
    d.add_argument("--dash-port",  type=int, default=5000, metavar="PORT")
    d.add_argument("--enable-auth",action="store_true", help="Enable HTTP basic auth")

    ap.add_argument("--config",    default="config.yaml", metavar="FILE")
    ap.add_argument("--quiet",     action="store_true", help="Suppress progress output")
    ap.add_argument("--no-logo",   action="store_true", help="Hide ASCII banner")
    ap.add_argument("--version",   action="version",   version="AegisScan 3.0")
    return ap


def main() -> None:
    ap   = build_cli()
    if len(sys.argv) == 1:
        ap.print_help(); sys.exit(0)
    args = ap.parse_args()

    if not args.no_logo:
        print(BANNER)

    cfg  = _load_config(args.config)
    repo = Repository(args.db_path)
    migrate(args.db_path)   # apply any pending schema migrations

    try:
        if args.scan:
            asyncio.run(_run_scan(
                args.scan, args.ports, args.timing,
                repo, not args.no_banner, args.quiet,
            ))

        elif args.banner:
            if not args.port:
                log.error("--port required for --banner"); sys.exit(1)
            async def _grab():
                e = ScanEngine(grab_banners=True, progress_cb=lambda _: None)
                r = await e.scan_host(args.banner, [args.port])
                if r.open_ports and r.open_ports[0].banner:
                    print(f"\n  BANNER ({args.banner}:{args.port})")
                    print(f"  {'─'*50}")
                    print(f"  {r.open_ports[0].banner}")
                elif r.open_ports:
                    print("  Port open but no banner returned")
                else:
                    print("  Port closed or filtered")
            asyncio.run(_grab())

        elif args.recon:
            wr = WebRecon()
            async def _run_recon():
                result = await wr.recon(
                    args.recon,
                    check_subdomains=args.subdomains,
                    grab_http=True,
                )
                wr.print_recon(result)
            asyncio.run(_run_recon())

        elif args.analyze:
            data = repo.get_scan(args.analyze)
            if not data:
                log.error(f"Scan {args.analyze} not found"); sys.exit(1)
            pa = PortAnalyzer()
            dominance, os_dist = pa.analyze(data)
            hosts = [h for h in data.get("hosts", []) if h.get("is_alive")]
            print(pa.format_report(dominance, os_dist, len(hosts)))

        elif args.benchmark:
            asyncio.run(_benchmark(args.benchmark, args.ports, args.timing))

        elif args.history is not None:
            show_history(repo, args.history)

        elif args.report:
            generate_report(repo, args.report, args.format)

        elif args.dashboard:
            dash_cfg = {
                **cfg.get("dashboard", {}),
                "host":        args.host,
                "port":        args.dash_port,
                "enable_auth": args.enable_auth,
            }
            from dashboard.app import run_dashboard
            run_dashboard(dash_cfg, repo)

        elif args.clear_db:
            confirm = input("  [!] Delete ALL records from database? (yes/no): ")
            if confirm.strip().lower() == "yes":
                repo.clear_all()
                print("  ✓ Database cleared")
            else:
                print("  Cancelled")

    except KeyboardInterrupt:
        print("\n  [!] Interrupted by user")
        sys.exit(0)
    except Exception as exc:
        log.exception(f"Fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
