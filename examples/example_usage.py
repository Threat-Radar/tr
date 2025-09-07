#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from threat_radar.core.github_integration import GitHubIntegration

def main():
    try:
        client = GitHubIntegration()
        print(f"Connected as: {client.user.login}")
        
        repo_name = "octocat/Hello-World"
        print(f"\n=== Repository Info: {repo_name} ===")
        repo_info = client.get_repository_info(repo_name)
        for key, value in repo_info.items():
            print(f"{key}: {value}")
        
        print(f"\n=== Your Repositories ===")
        user_repos = client.list_user_repositories()
        for repo in user_repos[:5]:  # Show first 5
            print(f"- {repo.full_name} ({repo.language}) - ⭐ {repo.stargazers_count}")
        
        print(f"\n=== Search: Python repositories ===")
        search_results = client.search_repositories("language:python", sort="stars")
        for repo in search_results[:3]:  # Show top 3
            print(f"- {repo.full_name} - ⭐ {repo.stargazers_count}")
        
        print(f"\n=== User Info ===")
        user_info = client.get_user_info()
        print(f"Name: {user_info['name']}")
        print(f"Public Repos: {user_info['public_repos']}")
        print(f"Followers: {user_info['followers']}")
        
    except ValueError as e:
        print(f"Error: {e}")
        print("\nTo use this script:")
        print("1. Get a GitHub personal access token from: https://github.com/settings/tokens")
        print("2. Create a .env file with: GITHUB_ACCESS_TOKEN=your_token_here")
        print("3. Or set the environment variable: export GITHUB_ACCESS_TOKEN=your_token")
    
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()