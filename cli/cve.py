import json, typer
from typing import List, Optional

app = typer.Typer(help="CVE operations (mock)")

@app.command("get")
def get(ids: List[str] = typer.Argument(...), jsonl: bool = True):
    """
    Mock: echo the requested IDs as normalized JSON objects.
    """
    for cve_id in ids:
        row = {"id": cve_id, "summary": None, "cvss": None, "cpes": []}
        print(json.dumps(row) if jsonl else json.dumps({"results": [row]}, indent=2))

@app.command("search")
def search(
    q: str = typer.Argument(..., help="keywords or CPE"),
    cpe: Optional[str] = typer.Option(None),
    limit: int = typer.Option(100, min=1, max=2000),
    jsonl: bool = True,
):
    """
    Mock: emit synthetic hits carrying your query params.
    """
    for i in range(1, min(limit, 5) + 1):
        row = {"id": f"MOCK-CVE-{i:04d}", "query": q, "cpe": cpe, "summary": None, "cvss": None}
        print(json.dumps(row) if jsonl else json.dumps({"results": [row]}, indent=2))

@app.command("cache")
def cache(op: str = typer.Argument("warm", help="warm|show|clear (mock only)")):
    """
    Mock cache ops.
    """
    print(json.dumps({"op": op, "status": "ok", "note": "mock only"}))
