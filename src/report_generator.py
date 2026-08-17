import json
from pathlib import Path
from datetime import datetime

def save_report(report, output_dir="reports_output"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = datetime.now().strftime("session_%Y%m%d_%H%M%S.json")
    path = Path(output_dir) / filename
    path.write_text(json.dumps(report, indent=4), encoding="utf-8")
    return str(path)
