#!/usr/bin/env python3

import os
import subprocess
import sys

def run_command(cmd):
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    print(result.stdout)
    return True

def main():
    print("Setting up Threat Radar development environment...")
    
    # Change to project root directory
    project_root = os.path.dirname(os.path.dirname(__file__))
    os.chdir(project_root)
    print(f"Working in: {os.getcwd()}")
    
    # Create virtual environment if it doesn't exist
    venv_dir = "venv"
    if not os.path.exists(venv_dir):
        print("Creating virtual environment...")
        if not run_command("python3 -m venv venv"):
            print("Failed to create virtual environment")
            return 1
    
    # Determine activation script path
    if os.name == 'nt':  # Windows
        pip_cmd = "venv\\Scripts\\pip"
    else:  # Unix/Linux/macOS
        pip_cmd = "venv/bin/pip"
    
    # Install package in development mode
    if not run_command(f"{pip_cmd} install -e .[dev]"):
        print("Failed to install package in development mode")
        return 1
    
    # Create .env file if it doesn't exist
    env_file = ".env"
    if not os.path.exists(env_file):
        print(f"Creating {env_file} from template...")
        with open(".env.example", "r") as src:
            with open(env_file, "w") as dst:
                dst.write(src.read())
        print(f"Please edit {env_file} and add your GitHub access token")
    
    print("\nDevelopment environment setup complete!")
    print("Next steps:")
    print("1. Activate virtual environment: source venv/bin/activate")
    print("2. Edit .env and add your GitHub access token")
    print("3. Run tests: pytest")
    print("4. Run example: python examples/example_usage.py")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())