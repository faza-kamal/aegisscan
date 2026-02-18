"""AegisScan Reporting — Public API

Generates PDF, HTML, and JSON reports from scan data.

Usage:
    from reporting import ReportGenerator
    gen = ReportGenerator(output_dir="reports")
    path = gen.generate(scan_data, fmt="html")
"""
from reporting.report_generator import ReportGenerator

__all__ = [
    "ReportGenerator",
]
