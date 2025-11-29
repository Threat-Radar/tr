"""Health check commands for Docker deployment and monitoring."""

import typer
import json
import subprocess
import sys
from typing import Dict, Any
from datetime import datetime
from pathlib import Path

app = typer.Typer(help="Health check and system status commands")


def check_docker_daemon() -> Dict[str, Any]:
    """Check if Docker daemon is accessible."""
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return {
            "status": "healthy" if result.returncode == 0 else "unhealthy",
            "accessible": result.returncode == 0,
            "message": (
                "Docker daemon is accessible"
                if result.returncode == 0
                else "Docker daemon not accessible"
            ),
        }
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {
            "status": "unhealthy",
            "accessible": False,
            "message": f"Docker daemon check failed: {str(e)}",
        }


def check_grype() -> Dict[str, Any]:
    """Check if Grype is installed and database is available."""
    try:
        # Check if grype is installed
        result = subprocess.run(["grype", "version"], capture_output=True, timeout=5)

        if result.returncode != 0:
            return {
                "status": "unhealthy",
                "installed": False,
                "message": "Grype not installed",
            }

        version = result.stdout.decode().strip().split("\n")[0]

        # Check database status
        db_result = subprocess.run(
            ["grype", "db", "status"], capture_output=True, timeout=10
        )

        db_healthy = db_result.returncode == 0

        return {
            "status": "healthy" if db_healthy else "degraded",
            "installed": True,
            "version": version,
            "database_status": "available" if db_healthy else "unavailable",
            "message": f"Grype {version} installed"
            + (", database available" if db_healthy else ", database needs update"),
        }
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {
            "status": "unhealthy",
            "installed": False,
            "message": f"Grype check failed: {str(e)}",
        }


def check_syft() -> Dict[str, Any]:
    """Check if Syft is installed."""
    try:
        result = subprocess.run(["syft", "version"], capture_output=True, timeout=5)

        if result.returncode != 0:
            return {
                "status": "unhealthy",
                "installed": False,
                "message": "Syft not installed",
            }

        version = result.stdout.decode().strip().split("\n")[0]

        return {
            "status": "healthy",
            "installed": True,
            "version": version,
            "message": f"Syft {version} installed",
        }
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {
            "status": "unhealthy",
            "installed": False,
            "message": f"Syft check failed: {str(e)}",
        }


def check_storage() -> Dict[str, Any]:
    """Check if storage directories are writable."""
    storage_paths = [
        Path("./storage/cve_storage"),
        Path("./storage/ai_analysis"),
        Path("./storage/graph_storage"),
        Path("./cache"),
        Path("./logs"),
    ]

    issues = []
    for path in storage_paths:
        if not path.exists():
            try:
                path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                issues.append(f"{path}: cannot create - {str(e)}")
        elif not path.is_dir():
            issues.append(f"{path}: exists but is not a directory")
        elif not (path.stat().st_mode & 0o200):  # Check write permission
            issues.append(f"{path}: not writable")

    if issues:
        return {
            "status": "degraded",
            "writable": False,
            "issues": issues,
            "message": f"Storage issues found: {', '.join(issues)}",
        }

    return {
        "status": "healthy",
        "writable": True,
        "message": "All storage paths are accessible and writable",
    }


def get_system_info() -> Dict[str, Any]:
    """Get system information."""
    import platform

    return {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
    }


@app.command()
def check(
    json_output: bool = typer.Option(False, "--json", help="Output in JSON format"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed information"
    ),
):
    """
    Perform comprehensive health check of Threat Radar components.

    Checks:
    - Docker daemon accessibility
    - Grype installation and database status
    - Syft installation
    - Storage directory permissions

    Exit codes:
    - 0: All checks passed (healthy)
    - 1: Some checks failed (degraded)
    - 2: Critical checks failed (unhealthy)
    """
    from ..utils.version import __version__

    # Perform all checks
    checks = {
        "docker": check_docker_daemon(),
        "grype": check_grype(),
        "syft": check_syft(),
        "storage": check_storage(),
    }

    # Determine overall status
    statuses = [check["status"] for check in checks.values()]
    if all(s == "healthy" for s in statuses):
        overall_status = "healthy"
        exit_code = 0
    elif any(s == "unhealthy" for s in statuses):
        overall_status = "unhealthy"
        exit_code = 2
    else:
        overall_status = "degraded"
        exit_code = 1

    # Build response
    response = {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": __version__,
        "checks": checks,
    }

    if verbose:
        response["system"] = get_system_info()

    # Output results
    if json_output:
        typer.echo(json.dumps(response, indent=2))
    else:
        # Human-readable output
        status_colors = {
            "healthy": typer.colors.GREEN,
            "degraded": typer.colors.YELLOW,
            "unhealthy": typer.colors.RED,
        }

        status_symbols = {"healthy": "✓", "degraded": "⚠", "unhealthy": "✗"}

        typer.echo("\n" + "=" * 60)
        typer.echo(f"  Threat Radar Health Check (v{__version__})")
        typer.echo("=" * 60 + "\n")

        # Overall status
        typer.secho(
            f"Overall Status: {status_symbols[overall_status]} {overall_status.upper()}",
            fg=status_colors[overall_status],
            bold=True,
        )
        typer.echo("")

        # Individual checks
        typer.echo("Component Checks:")
        typer.echo("-" * 60)

        for component, check_result in checks.items():
            status = check_result["status"]
            symbol = status_symbols[status]
            color = status_colors[status]

            typer.secho(
                f"  {symbol} {component.upper():12} - {check_result['message']}",
                fg=color,
            )

        typer.echo("\n" + "=" * 60)

        if verbose and "system" in response:
            typer.echo("\nSystem Information:")
            typer.echo("-" * 60)
            for key, value in response["system"].items():
                typer.echo(f"  {key}: {value}")
            typer.echo("")

    sys.exit(exit_code)


@app.command()
def ping():
    """
    Quick health check that returns immediately.

    Returns exit code 0 if service is running, 1 otherwise.
    Suitable for Docker HEALTHCHECK and load balancer health probes.
    """
    try:
        from ..utils.version import __version__

        typer.echo(f"pong - Threat Radar v{__version__}")
        sys.exit(0)
    except Exception as e:
        typer.echo(f"error: {str(e)}", err=True)
        sys.exit(1)


@app.command()
def version():
    """Display Threat Radar version and dependency versions."""
    from ..utils.version import __version__

    typer.echo(f"Threat Radar v{__version__}")

    # Check dependencies
    deps = {
        "Docker": check_docker_daemon(),
        "Grype": check_grype(),
        "Syft": check_syft(),
    }

    typer.echo("\nDependencies:")
    for name, dep_check in deps.items():
        if dep_check.get("installed") or dep_check.get("accessible"):
            version = dep_check.get("version", "installed")
            typer.echo(f"  ✓ {name}: {version}")
        else:
            typer.echo(f"  ✗ {name}: not installed")


if __name__ == "__main__":
    app()
