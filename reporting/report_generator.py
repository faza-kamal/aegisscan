"""
reporting/report_generator.py
Generate PDF, HTML, and JSON reports from scan data.
Uses ReportLab for PDF (falls back gracefully if not installed).
Pure template rendering for HTML (no external deps beyond Jinja2/stdlib).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─── Report Generator ────────────────────────────────────────────────────────

class ReportGenerator:
    """
    Generate reports in PDF, HTML, or JSON format.
    Layering: only imports database.repository (via passed dict data).
    Does NOT import core or dashboard.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, scan_data: dict, fmt: str = "json") -> Optional[str]:
        """
        Generate report for scan data dict.

        Args:
            scan_data: Dict from repository.get_scan()
            fmt: 'json' | 'html' | 'pdf'

        Returns:
            Path to generated file, or None on error.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        sid = scan_data.get("id", "unknown")
        base = self.output_dir / f"aegisscan_scan{sid}_{ts}"

        try:
            if fmt == "json":
                return self._json(scan_data, f"{base}.json")
            elif fmt == "html":
                return self._html(scan_data, f"{base}.html")
            elif fmt == "pdf":
                return self._pdf(scan_data, f"{base}.pdf")
            else:
                raise ValueError(f"Unknown format: {fmt}")
        except Exception as exc:
            print(f"[ERROR] Report generation failed: {exc}")
            return None

    # ── JSON ─────────────────────────────────────────────────────────────────

    def _json(self, data: dict, path: str) -> str:
        with open(path, "w") as f:
            json.dump({
                "report_generated": datetime.now(timezone.utc).isoformat(),
                "aegisscan_version": "3.0",
                "scan": data,
            }, f, indent=2, default=str)
        return path

    # ── HTML ─────────────────────────────────────────────────────────────────

    def _html(self, data: dict, path: str) -> str:
        hosts_html = ""
        for host in data.get("hosts", []):
            if not host.get("is_alive"):
                continue
            ports_rows = ""
            for p in host.get("ports", []):
                banner = (p.get("banner") or "")[:80].replace("<", "&lt;").replace(">", "&gt;")
                ports_rows += f"""
                <tr>
                  <td><strong>{p['port']}</strong></td>
                  <td><span class="badge-open">{p['state']}</span></td>
                  <td>{p['service']}</td>
                  <td class="banner-cell">{banner}</td>
                </tr>"""
            os_guess = host.get("os_guess", "")
            ports_section = f"""
            <table>
              <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr></thead>
              <tbody>{ports_rows}</tbody>
            </table>""" if ports_rows else "<p class='muted'>No open ports detected</p>"

            hosts_html += f"""
            <div class="host-card">
              <div class="host-header">
                <span class="host-ip">{host['ip']}</span>
                <span class="host-name">{host.get('hostname') or ''}</span>
                {f'<span class="os-badge">{os_guess}</span>' if os_guess else ''}
              </div>
              {ports_section}
            </div>"""

        dur = f"{data['duration_s']:.1f}s" if data.get('duration_s') else "—"
        html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AegisScan Report — Scan #{data.get('id')}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:30px}}
h1{{color:#60a5fa;font-size:2rem;margin-bottom:4px}}
.meta{{color:#64748b;margin-bottom:30px;font-size:.9rem}}
.info-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:30px}}
.info-card{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:18px}}
.info-card .val{{font-size:1.8rem;font-weight:700;color:#60a5fa}}
.info-card .lbl{{color:#94a3b8;font-size:.8rem;text-transform:uppercase;margin-top:4px}}
.host-card{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin-bottom:20px}}
.host-header{{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}}
.host-ip{{background:#1e40af;color:#fff;padding:4px 14px;border-radius:20px;font-weight:600}}
.host-name{{color:#94a3b8}}
.os-badge{{background:#065f46;color:#6ee7b7;padding:3px 10px;border-radius:10px;font-size:.8rem}}
table{{width:100%;border-collapse:collapse;font-size:.88rem}}
th{{background:#0f172a;color:#60a5fa;padding:10px;text-align:left;text-transform:uppercase;font-size:.75rem}}
td{{padding:9px 10px;border-bottom:1px solid #1e293b}}
tr:hover td{{background:#1e3a5f}}
.badge-open{{background:#064e3b;color:#6ee7b7;padding:2px 8px;border-radius:10px;font-size:.78rem;font-weight:600}}
.banner-cell{{color:#64748b;font-family:monospace;font-size:.8rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.muted{{color:#64748b;font-style:italic;padding:10px 0}}
footer{{margin-top:40px;text-align:center;color:#475569;font-size:.8rem;border-top:1px solid #1e293b;padding-top:20px}}
h2{{color:#f1f5f9;margin-bottom:20px;font-size:1.1rem}}
</style></head><body>
<h1>🛡️ AegisScan Security Report</h1>
<p class="meta">Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} · AegisScan v3.0</p>
<div class="info-grid">
  <div class="info-card"><div class="val">#{data.get('id')}</div><div class="lbl">Scan ID</div></div>
  <div class="info-card"><div class="val">{data.get('target','—')}</div><div class="lbl">Target</div></div>
  <div class="info-card"><div class="val">{data.get('hosts_found',0)}</div><div class="lbl">Hosts Found</div></div>
  <div class="info-card"><div class="val">{data.get('ports_open',0)}</div><div class="lbl">Open Ports</div></div>
  <div class="info-card"><div class="val">{dur}</div><div class="lbl">Duration</div></div>
  <div class="info-card"><div class="val">{data.get('timing','normal')}</div><div class="lbl">Timing Profile</div></div>
</div>
<h2>Discovered Hosts</h2>
{hosts_html or '<p class="muted">No alive hosts found.</p>'}
<footer>AegisScan v3.0 · For authorized use only · {datetime.now(timezone.utc).year}</footer>
</body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    # ── PDF ──────────────────────────────────────────────────────────────────

    def _pdf(self, data: dict, path: str) -> str:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                SimpleDocTemplate, Table, TableStyle,
                Paragraph, Spacer, HRFlowable,
            )
        except ImportError:
            print("[WARNING] reportlab not installed — generating HTML instead")
            return self._html(data, path.replace(".pdf", ".html"))

        doc = SimpleDocTemplate(path, pagesize=A4,
                                topMargin=2*cm, bottomMargin=2*cm,
                                leftMargin=2*cm, rightMargin=2*cm)
        styles = getSampleStyleSheet()
        story = []

        DARK  = colors.HexColor("#1e293b")
        BLUE  = colors.HexColor("#3b82f6")
        GREEN = colors.HexColor("#059669")
        LIGHT = colors.HexColor("#e2e8f0")
        GRAY  = colors.HexColor("#94a3b8")

        title_style = ParagraphStyle("Title", parent=styles["Title"],
                                     fontSize=22, textColor=BLUE, spaceAfter=6)
        h2_style    = ParagraphStyle("H2", parent=styles["Heading2"],
                                     fontSize=13, textColor=DARK, spaceBefore=14, spaceAfter=8)
        body_style  = ParagraphStyle("Body", parent=styles["Normal"],
                                     fontSize=9, textColor=DARK)
        mono_style  = ParagraphStyle("Mono", parent=styles["Code"],
                                     fontSize=7.5, textColor=GRAY)

        # Title
        story.append(Paragraph("🛡 AegisScan Security Report", title_style))
        story.append(Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · v3.0",
            ParagraphStyle("sub", parent=styles["Normal"], fontSize=8, textColor=GRAY)
        ))
        story.append(Spacer(1, 0.4*cm))
        story.append(HRFlowable(width="100%", color=BLUE, thickness=1.5))
        story.append(Spacer(1, 0.3*cm))

        # Summary table
        dur = f"{data['duration_s']:.1f}s" if data.get('duration_s') else "—"
        summary_data = [
            ["Scan ID", str(data.get("id", "—")),
             "Target", data.get("target", "—")],
            ["Hosts Found", str(data.get("hosts_found", 0)),
             "Open Ports", str(data.get("ports_open", 0))],
            ["Duration", dur,
             "Timing", data.get("timing", "normal")],
        ]
        t = Table(summary_data, colWidths=[3*cm, 5*cm, 3*cm, 5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (0,-1), DARK),
            ("BACKGROUND",  (2,0), (2,-1), DARK),
            ("TEXTCOLOR",   (0,0), (0,-1), LIGHT),
            ("TEXTCOLOR",   (2,0), (2,-1), LIGHT),
            ("FONTNAME",    (0,0), (-1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("PADDING",     (0,0), (-1,-1), 7),
            ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#334155")),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.5*cm))

        # Hosts
        story.append(Paragraph("Discovered Hosts", h2_style))
        alive_hosts = [h for h in data.get("hosts", []) if h.get("is_alive")]

        if not alive_hosts:
            story.append(Paragraph("No alive hosts found.", body_style))
        else:
            for host in alive_hosts:
                story.append(Spacer(1, 0.2*cm))
                hostname = host.get("hostname") or ""
                os_info  = host.get("os_guess") or ""
                story.append(Paragraph(
                    f"<b>{host['ip']}</b>  {hostname}  {os_info}",
                    ParagraphStyle("hosthead", parent=styles["Normal"],
                                   fontSize=10, textColor=BLUE, spaceBefore=6)
                ))

                ports = host.get("ports", [])
                if ports:
                    port_data = [["Port", "State", "Service", "Banner"]]
                    for p in ports:
                        banner = (p.get("banner") or "")[:60]
                        port_data.append([
                            str(p["port"]),
                            p.get("state", "open"),
                            p.get("service", ""),
                            banner,
                        ])
                    pt = Table(port_data, colWidths=[1.5*cm, 2*cm, 4*cm, 9*cm])
                    pt.setStyle(TableStyle([
                        ("BACKGROUND",  (0,0), (-1,0), BLUE),
                        ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
                        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
                        ("FONTSIZE",    (0,0), (-1,-1), 8),
                        ("PADDING",     (0,0), (-1,-1), 5),
                        ("ROWBACKGROUNDS", (0,1), (-1,-1),
                         [colors.white, colors.HexColor("#f8fafc")]),
                        ("GRID",        (0,0), (-1,-1), 0.4, colors.HexColor("#e2e8f0")),
                        ("TEXTCOLOR",   (1,1), (1,-1), GREEN),
                    ]))
                    story.append(pt)
                else:
                    story.append(Paragraph("No open ports.", mono_style))

        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", color=GRAY, thickness=0.5))
        story.append(Paragraph(
            "AegisScan v3.0 · For authorized security testing only",
            ParagraphStyle("footer", parent=styles["Normal"], fontSize=7,
                           textColor=GRAY, alignment=1)
        ))

        doc.build(story)
        return path
