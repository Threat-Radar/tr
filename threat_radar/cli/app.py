import typer
from . import cve as cve_cmd, sbom, enrich, config, hash, docker, ai, report

app = typer.Typer(help="threat: mock CLI (commands only)")

# sub-commands (map 1:1 to your UX)
app.add_typer(cve_cmd.app, name="cve")
app.add_typer(sbom.app, name="sbom")
app.add_typer(enrich.app, name="enrich")
app.add_typer(config.app, name="config")
app.add_typer(hash.app, name="hash")
app.add_typer(docker.app, name="docker")
app.add_typer(ai.app, name="ai")
app.add_typer(report.app, name="report")

def main() -> None:
    app()
