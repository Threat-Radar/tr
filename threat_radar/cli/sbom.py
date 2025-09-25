from pathlib import Path
import json, typer

app = typer.Typer(help="SBOM ops (mock)")

@app.command("read")
def read(path: Path = typer.Argument(..., exists=True, readable=True), jsonl: bool = True):
    """
    Mock: do not parse; just emit a placeholder component list.
    """
    comps = [
        {"name": "example-lib", "version": "1.0.0", "purl": None, "cpe": None},
        {"name": "another-lib", "version": "2.3.4", "purl": None, "cpe": None},
    ]
    if jsonl:
        for c in comps:
            print(json.dumps(c))
    else:
        print(json.dumps({"components": comps}, indent=2))
