from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent / "templates"
REPORTS_DIR = Path(__file__).parent.parent.parent / "data" / "reports"


def _env() -> Environment:
    return Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)


def _context(job, findings, credentials, flags) -> dict:
    return {
        "job": job,
        "findings": findings,
        "credentials": credentials,
        "flags": flags,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "finding_counts": {
            "open_port": sum(1 for f in findings if f.finding_type == "open_port"),
            "vuln": sum(1 for f in findings if f.finding_type in ("vuln", "sqli", "lfi", "xss")),
            "exploit": sum(1 for f in findings if f.finding_type == "exploit"),
        },
    }


async def generate_html(job, findings, credentials, flags) -> str:
    env = _env()
    template = env.get_template("report.html.j2")
    return template.render(**_context(job, findings, credentials, flags))


async def generate_pdf(job, findings, credentials, flags) -> str:
    html = await generate_html(job, findings, credentials, flags)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    pdf_path = REPORTS_DIR / f"report-{job.id[:8]}.pdf"
    try:
        import weasyprint
        weasyprint.HTML(string=html).write_pdf(str(pdf_path))
    except ImportError:
        # Fallback: save as HTML with .pdf extension (user can print-to-PDF)
        pdf_path = REPORTS_DIR / f"report-{job.id[:8]}.html"
        pdf_path.write_text(html, encoding="utf-8")
    return str(pdf_path)
