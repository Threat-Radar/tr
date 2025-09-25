import typer
from . import cve as cve_cmd, cvss, sbom, enrich, config, hash

app = typer.Typer(help="threat: mock CLI (commands only)")

# sub-commands (map 1:1 to your UX)
app.add_typer(cve_cmd.app, name="cve")
app.add_typer(cvss.app, name="cvss")
app.add_typer(sbom.app, name="sbom")
app.add_typer(enrich.app, name="enrich")
app.add_typer(config.app, name="config")
app.add_typer(hash.app, name="hash")

def main() -> None:
    app()
