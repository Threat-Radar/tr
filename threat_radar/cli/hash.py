import typer
from pathlib import Path
from typing import Optional
from ..utils.hasher import Hasher

app = typer.Typer(help="File hashing utilities")

@app.command()
def file(
    file_path: Path = typer.Argument(..., help="Path to the file to hash"),
    algorithm: str = typer.Option("sha256", "--algorithm", "-a", help="Hash algorithm (sha256 or md5)"),
    output_format: str = typer.Option("hex", "--format", "-f", help="Output format (hex or text)")
):
    """Generate hash of a file with specified algorithm and output format"""

    try:
        hash_value = Hasher.file_hash(str(file_path), algorithm, output_format)
        typer.echo(f"{algorithm.upper()} ({output_format}): {hash_value}")

    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    except FileNotFoundError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    except PermissionError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    except Exception as e:
        typer.echo(f"Unexpected error: {e}", err=True)
        raise typer.Exit(1)

if __name__ == "__main__":
    app()