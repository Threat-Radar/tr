from pathlib import Path
import json, typer

app = typer.Typer(help="config helpers (mock)")

@app.command("path")
def path():
    print(str(Path("~/.threat").expanduser()))

@app.command("init")
def init(dir: Path = typer.Option(Path("~/.threat").expanduser())):
    (dir / "cache").mkdir(parents=True, exist_ok=True)
    print(json.dumps({"ok": True, "cache_dir": str(dir / "cache")}))
