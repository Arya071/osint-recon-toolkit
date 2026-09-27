import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate(domain: str, results: dict, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_domain = domain.replace("/", "_")

    json_path = output_dir / f"{safe_domain}_{timestamp}.json"
    json_path.write_text(json.dumps(results, indent=2))

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("report_template.html")
    html = template.render(
        domain=domain,
        generated_at=datetime.now(timezone.utc).isoformat(),
        **results,
    )
    html_path = output_dir / f"{safe_domain}_{timestamp}.html"
    html_path.write_text(html)

    return json_path, html_path
