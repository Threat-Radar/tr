import json, typer
from pathlib import Path

app = typer.Typer(help="enrich SBOM components with CVEs (mock)")

@app.command()
def run(sbom: Path = typer.Argument(..., exists=True, readable=True), jsonl: bool = True):
    """
    Mock enrichment: pairs fake CVEs with fake components.
    """
    findings = [
        {"component": {"name": "example-lib", "version": "1.0.0"},
         "cve": {"id": "MOCK-CVE-0001"}, "risk": None},
        {"component": {"name": "another-lib", "version": "2.3.4"},
         "cve": {"id": "MOCK-CVE-0002"}, "risk": None},
    ]
    if jsonl:
        for f in findings:
            print(json.dumps(f))
    else:
        print(json.dumps({"findings": findings}, indent=2))
    