import json, typer

app = typer.Typer(help="CVSS helpers (mock)")

@app.command("parse")
def parse(vector: str = typer.Argument(..., help="CVSS v3.x vector string")):
    """
    Mock parse: returns a minimal structure with the original vector.
    """
    print(json.dumps({"vector": vector, "version": "3.1", "metrics": {}, "base_score": None}))

@app.command("score")
def score(
    vector: str = typer.Option("", help="CVSS v3.x vector"),
    base: float = typer.Option(0.0, help="override score (mock)"),
    jsonout: bool = True,
):
    """
    Mock score: if vector provided, echoes it; otherwise uses --base.
    """
    out = {"vector": vector or None, "score": base if base else None}
    print(json.dumps(out) if jsonout else out)
