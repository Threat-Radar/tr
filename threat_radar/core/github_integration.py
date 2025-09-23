import os
from typing import List, Dict, Any, Optional
from github import Github, Repository, Issue, PullRequest
from dotenv import load_dotenv

load_dotenv()


class GitHubIntegration:
    def __init__(self, access_token: Optional[str] = None):
        self.token = access_token or os.getenv('GITHUB_ACCESS_TOKEN')
        if not self.token:
            raise ValueError("GitHub access token is required. Set GITHUB_ACCESS_TOKEN environment variable or pass token directly.")
        
        self.client = Github(self.token)
        self.user = self.client.get_user()
    
    def get_repository(self, repo_name: str) -> Repository:
        return self.client.get_repo(repo_name)
    
    def list_user_repositories(self, user: Optional[str] = None) -> List[Repository]:
        if user:
            return list(self.client.get_user(user).get_repos())
        return list(self.user.get_repos())
    
    def get_repository_info(self, repo_name: str) -> Dict[str, Any]:
        repo = self.get_repository(repo_name)
        return {
            'name': repo.name,
            'full_name': repo.full_name,
            'description': repo.description,
            'language': repo.language,
            'stars': repo.stargazers_count,
            'forks': repo.forks_count,
            'open_issues': repo.open_issues_count,
            'created_at': repo.created_at,
            'updated_at': repo.updated_at,
            'clone_url': repo.clone_url,
            'html_url': repo.html_url
        }
    
    def analyze_security_issues(self, repo_name: str) -> List[Dict[str, Any]]:
        """Analyze repository for potential security issues"""
        repo = self.get_repository(repo_name)
        security_issues = []
        
        # Check for security-related issues
        issues = repo.get_issues(state='all', labels=['security', 'vulnerability', 'cve'])
        for issue in issues:
            security_issues.append({
                'title': issue.title,
                'body': issue.body,
                'state': issue.state,
                'created_at': issue.created_at,
                'labels': [label.name for label in issue.labels],
                'url': issue.html_url
            })
        
        return security_issues
    
    def get_repository_dependencies(self, repo_name: str) -> List[Dict[str, Any]]:
        """Extract dependencies from common dependency files"""
        repo = self.get_repository(repo_name)
        dependencies = []
        
        # Check common dependency files
        dep_files = ['requirements.txt', 'package.json', 'Pipfile', 'pyproject.toml', 'pom.xml']
        
        for file_name in dep_files:
            try:
                content = repo.get_contents(file_name)
                dependencies.append({
                    'file': file_name,
                    'content': content.decoded_content.decode('utf-8'),
                    'path': content.path
                })
            except:
                continue
        
        return dependencies
    
    def search_repositories(self, query: str, sort: str = 'stars', order: str = 'desc') -> List[Repository]:
        return list(self.client.search_repositories(query=query, sort=sort, order=order))
    
    def get_user_info(self, username: Optional[str] = None) -> Dict[str, Any]:
        user = self.client.get_user(username) if username else self.user
        return {
            'login': user.login,
            'name': user.name,
            'email': user.email,
            'company': user.company,
            'location': user.location,
            'bio': user.bio,
            'public_repos': user.public_repos,
            'followers': user.followers,
            'following': user.following,
            'created_at': user.created_at,
            'html_url': user.html_url
        }