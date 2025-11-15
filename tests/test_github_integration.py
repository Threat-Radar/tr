"""Comprehensive tests for GitHub integration."""

import pytest
import os
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from github import Github, Repository, Issue, Label, NamedUser, ContentFile
from github.GithubException import GithubException, UnknownObjectException

from threat_radar.core.github_integration import GitHubIntegration


@pytest.fixture
def mock_github():
    """Create a mock GitHub client."""
    with patch('threat_radar.core.github_integration.Github') as mock_github_class:
        mock_client = MagicMock(spec=Github)
        mock_github_class.return_value = mock_client
        yield mock_client


@pytest.fixture
def mock_repository():
    """Create a mock GitHub repository."""
    repo = MagicMock(spec=Repository.Repository)
    repo.name = "test-repo"
    repo.full_name = "user/test-repo"
    repo.description = "Test repository"
    repo.language = "Python"
    repo.stargazers_count = 100
    repo.forks_count = 25
    repo.open_issues_count = 5
    repo.created_at = datetime(2023, 1, 1)
    repo.updated_at = datetime(2023, 12, 1)
    repo.clone_url = "https://github.com/user/test-repo.git"
    repo.html_url = "https://github.com/user/test-repo"
    return repo


@pytest.fixture
def mock_user():
    """Create a mock GitHub user."""
    user = MagicMock(spec=NamedUser.NamedUser)
    user.login = "testuser"
    user.name = "Test User"
    user.email = "test@example.com"
    user.company = "Test Corp"
    user.location = "San Francisco"
    user.bio = "Test bio"
    user.public_repos = 50
    user.followers = 100
    user.following = 75
    user.created_at = datetime(2020, 1, 1)
    user.html_url = "https://github.com/testuser"
    return user


@pytest.fixture
def mock_issue():
    """Create a mock GitHub issue."""
    issue = MagicMock(spec=Issue.Issue)
    issue.title = "Security Vulnerability Found"
    issue.body = "CVE-2023-1234 affects this project"
    issue.state = "open"
    issue.created_at = datetime(2023, 11, 1)
    issue.html_url = "https://github.com/user/repo/issues/1"

    # Mock labels
    label1 = MagicMock(spec=Label.Label)
    label1.name = "security"
    label2 = MagicMock(spec=Label.Label)
    label2.name = "vulnerability"
    issue.labels = [label1, label2]

    return issue


class TestGitHubIntegrationInitialization:
    """Test GitHubIntegration initialization."""

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_init_with_env_token(self, mock_github, mock_user):
        """Test initialization with token from environment."""
        mock_github.get_user.return_value = mock_user

        integration = GitHubIntegration()

        assert integration.token == 'test-token'
        assert integration.client is not None
        assert integration.user is not None

    def test_init_with_explicit_token(self, mock_github, mock_user):
        """Test initialization with explicitly provided token."""
        mock_github.get_user.return_value = mock_user

        integration = GitHubIntegration(access_token='explicit-token')

        assert integration.token == 'explicit-token'
        assert integration.client is not None

    @patch.dict(os.environ, {}, clear=True)
    def test_init_without_token_raises_error(self):
        """Test that initialization without token raises error."""
        with pytest.raises(ValueError, match="GitHub access token is required"):
            GitHubIntegration()

    def test_init_explicit_token_overrides_env(self, mock_github, mock_user):
        """Test that explicit token overrides environment variable."""
        mock_github.get_user.return_value = mock_user

        with patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'env-token'}):
            integration = GitHubIntegration(access_token='explicit-token')

            assert integration.token == 'explicit-token'


class TestGetRepository:
    """Test getting repository information."""

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_get_repository_success(self, mock_github, mock_user, mock_repository):
        """Test getting a repository successfully."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.return_value = mock_repository

        integration = GitHubIntegration()
        repo = integration.get_repository("user/test-repo")

        assert repo == mock_repository
        mock_github.get_repo.assert_called_once_with("user/test-repo")

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_get_repository_not_found(self, mock_github, mock_user):
        """Test getting nonexistent repository."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.side_effect = UnknownObjectException(404, "Not Found")

        integration = GitHubIntegration()

        with pytest.raises(UnknownObjectException):
            integration.get_repository("user/nonexistent-repo")


class TestGetRepositoryInfo:
    """Test extracting repository information."""

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_get_repository_info_success(self, mock_github, mock_user, mock_repository):
        """Test extracting repository information."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.return_value = mock_repository

        integration = GitHubIntegration()
        info = integration.get_repository_info("user/test-repo")

        assert info['name'] == "test-repo"
        assert info['full_name'] == "user/test-repo"
        assert info['description'] == "Test repository"
        assert info['language'] == "Python"
        assert info['stars'] == 100
        assert info['forks'] == 25
        assert info['open_issues'] == 5
        assert info['clone_url'] == "https://github.com/user/test-repo.git"
        assert info['html_url'] == "https://github.com/user/test-repo"

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_get_repository_info_with_none_values(self, mock_github, mock_user):
        """Test repository info when some fields are None."""
        mock_github.get_user.return_value = mock_user

        repo = MagicMock(spec=Repository.Repository)
        repo.name = "test-repo"
        repo.full_name = "user/test-repo"
        repo.description = None  # No description
        repo.language = None  # No primary language
        repo.stargazers_count = 0
        repo.forks_count = 0
        repo.open_issues_count = 0
        repo.created_at = datetime(2023, 1, 1)
        repo.updated_at = datetime(2023, 12, 1)
        repo.clone_url = "https://github.com/user/test-repo.git"
        repo.html_url = "https://github.com/user/test-repo"

        mock_github.get_repo.return_value = repo

        integration = GitHubIntegration()
        info = integration.get_repository_info("user/test-repo")

        assert info['description'] is None
        assert info['language'] is None
        assert info['stars'] == 0


class TestListUserRepositories:
    """Test listing user repositories."""

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_list_own_repositories(self, mock_github, mock_user, mock_repository):
        """Test listing authenticated user's repositories."""
        mock_github.get_user.return_value = mock_user
        mock_user.get_repos.return_value = [mock_repository]

        integration = GitHubIntegration()
        repos = integration.list_user_repositories()

        assert len(repos) == 1
        assert repos[0] == mock_repository

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_list_other_user_repositories(self, mock_github, mock_user, mock_repository):
        """Test listing another user's repositories."""
        mock_github.get_user.side_effect = lambda user=None: mock_user if user else mock_user

        other_user = MagicMock(spec=NamedUser.NamedUser)
        other_user.get_repos.return_value = [mock_repository]
        mock_github.get_user.side_effect = lambda user=None: other_user if user == "otheruser" else mock_user

        integration = GitHubIntegration()
        repos = integration.list_user_repositories(user="otheruser")

        assert len(repos) == 1
        mock_github.get_user.assert_called_with("otheruser")

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_list_repositories_empty(self, mock_github, mock_user):
        """Test listing repositories when user has none."""
        mock_github.get_user.return_value = mock_user
        mock_user.get_repos.return_value = []

        integration = GitHubIntegration()
        repos = integration.list_user_repositories()

        assert len(repos) == 0


class TestAnalyzeSecurityIssues:
    """Test analyzing security issues."""

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_analyze_security_issues_success(self, mock_github, mock_user, mock_repository, mock_issue):
        """Test analyzing security issues in a repository."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.return_value = mock_repository
        mock_repository.get_issues.return_value = [mock_issue]

        integration = GitHubIntegration()
        issues = integration.analyze_security_issues("user/test-repo")

        assert len(issues) == 1
        assert issues[0]['title'] == "Security Vulnerability Found"
        assert issues[0]['state'] == "open"
        assert 'security' in issues[0]['labels']
        assert 'vulnerability' in issues[0]['labels']

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_analyze_security_issues_multiple(self, mock_github, mock_user, mock_repository):
        """Test analyzing multiple security issues."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.return_value = mock_repository

        # Create multiple issues
        issue1 = MagicMock(spec=Issue.Issue)
        issue1.title = "CVE-2023-0001"
        issue1.body = "Critical vulnerability"
        issue1.state = "open"
        issue1.created_at = datetime(2023, 11, 1)
        issue1.html_url = "https://github.com/user/repo/issues/1"
        label1 = MagicMock()
        label1.name = "security"
        issue1.labels = [label1]

        issue2 = MagicMock(spec=Issue.Issue)
        issue2.title = "CVE-2023-0002"
        issue2.body = "High severity issue"
        issue2.state = "closed"
        issue2.created_at = datetime(2023, 10, 1)
        issue2.html_url = "https://github.com/user/repo/issues/2"
        label2 = MagicMock()
        label2.name = "vulnerability"
        issue2.labels = [label2]

        mock_repository.get_issues.return_value = [issue1, issue2]

        integration = GitHubIntegration()
        issues = integration.analyze_security_issues("user/test-repo")

        assert len(issues) == 2
        assert issues[0]['title'] == "CVE-2023-0001"
        assert issues[1]['title'] == "CVE-2023-0002"

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_analyze_security_issues_none_found(self, mock_github, mock_user, mock_repository):
        """Test when no security issues are found."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.return_value = mock_repository
        mock_repository.get_issues.return_value = []

        integration = GitHubIntegration()
        issues = integration.analyze_security_issues("user/test-repo")

        assert len(issues) == 0


class TestGetRepositoryDependencies:
    """Test extracting repository dependencies."""

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_get_dependencies_requirements_txt(self, mock_github, mock_user, mock_repository):
        """Test extracting dependencies from requirements.txt."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.return_value = mock_repository

        # Mock requirements.txt content
        mock_content = MagicMock(spec=ContentFile.ContentFile)
        mock_content.decoded_content = b"flask==2.0.0\nrequests==2.28.0"
        mock_content.path = "requirements.txt"

        def get_contents_side_effect(filename):
            if filename == "requirements.txt":
                return mock_content
            raise Exception("File not found")

        mock_repository.get_contents.side_effect = get_contents_side_effect

        integration = GitHubIntegration()
        dependencies = integration.get_repository_dependencies("user/test-repo")

        assert len(dependencies) == 1
        assert dependencies[0]['file'] == "requirements.txt"
        assert "flask==2.0.0" in dependencies[0]['content']
        assert "requests==2.28.0" in dependencies[0]['content']

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_get_dependencies_multiple_files(self, mock_github, mock_user, mock_repository):
        """Test extracting dependencies from multiple files."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.return_value = mock_repository

        # Mock multiple dependency files
        mock_requirements = MagicMock(spec=ContentFile.ContentFile)
        mock_requirements.decoded_content = b"flask==2.0.0"
        mock_requirements.path = "requirements.txt"

        mock_package_json = MagicMock(spec=ContentFile.ContentFile)
        mock_package_json.decoded_content = b'{"dependencies": {"express": "^4.17.0"}}'
        mock_package_json.path = "package.json"

        def get_contents_side_effect(filename):
            if filename == "requirements.txt":
                return mock_requirements
            elif filename == "package.json":
                return mock_package_json
            raise Exception("File not found")

        mock_repository.get_contents.side_effect = get_contents_side_effect

        integration = GitHubIntegration()
        dependencies = integration.get_repository_dependencies("user/test-repo")

        assert len(dependencies) == 2
        file_names = [dep['file'] for dep in dependencies]
        assert "requirements.txt" in file_names
        assert "package.json" in file_names

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_get_dependencies_no_files_found(self, mock_github, mock_user, mock_repository):
        """Test when no dependency files are found."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.return_value = mock_repository
        mock_repository.get_contents.side_effect = Exception("File not found")

        integration = GitHubIntegration()
        dependencies = integration.get_repository_dependencies("user/test-repo")

        assert len(dependencies) == 0


class TestSearchRepositories:
    """Test searching repositories."""

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_search_repositories_success(self, mock_github, mock_user, mock_repository):
        """Test searching repositories."""
        mock_github.get_user.return_value = mock_user
        mock_github.search_repositories.return_value = [mock_repository]

        integration = GitHubIntegration()
        results = integration.search_repositories("vulnerability scanner")

        assert len(results) == 1
        assert results[0] == mock_repository
        mock_github.search_repositories.assert_called_once_with(
            query="vulnerability scanner",
            sort="stars",
            order="desc"
        )

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_search_repositories_custom_sort(self, mock_github, mock_user, mock_repository):
        """Test searching with custom sort parameters."""
        mock_github.get_user.return_value = mock_user
        mock_github.search_repositories.return_value = [mock_repository]

        integration = GitHubIntegration()
        results = integration.search_repositories(
            "python security",
            sort="updated",
            order="asc"
        )

        mock_github.search_repositories.assert_called_once_with(
            query="python security",
            sort="updated",
            order="asc"
        )

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_search_repositories_no_results(self, mock_github, mock_user):
        """Test searching with no results."""
        mock_github.get_user.return_value = mock_user
        mock_github.search_repositories.return_value = []

        integration = GitHubIntegration()
        results = integration.search_repositories("nonexistent-query-xyz")

        assert len(results) == 0


class TestGetUserInfo:
    """Test getting user information."""

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_get_own_user_info(self, mock_github, mock_user):
        """Test getting authenticated user's info."""
        mock_github.get_user.return_value = mock_user

        integration = GitHubIntegration()
        info = integration.get_user_info()

        assert info['login'] == "testuser"
        assert info['name'] == "Test User"
        assert info['email'] == "test@example.com"
        assert info['company'] == "Test Corp"
        assert info['public_repos'] == 50
        assert info['followers'] == 100

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_get_other_user_info(self, mock_github, mock_user):
        """Test getting another user's info."""
        mock_github.get_user.return_value = mock_user

        other_user = MagicMock(spec=NamedUser.NamedUser)
        other_user.login = "otheruser"
        other_user.name = "Other User"
        other_user.email = None
        other_user.company = "Other Corp"
        other_user.location = "New York"
        other_user.bio = "Other bio"
        other_user.public_repos = 25
        other_user.followers = 50
        other_user.following = 30
        other_user.created_at = datetime(2021, 1, 1)
        other_user.html_url = "https://github.com/otheruser"

        mock_github.get_user.side_effect = lambda user=None: other_user if user == "otheruser" else mock_user

        integration = GitHubIntegration()
        info = integration.get_user_info("otheruser")

        assert info['login'] == "otheruser"
        assert info['name'] == "Other User"
        assert info['email'] is None
        assert info['public_repos'] == 25


class TestGitHubIntegrationEdgeCases:
    """Test edge cases and error handling."""

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_rate_limit_handling(self, mock_github, mock_user):
        """Test handling of rate limit errors."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.side_effect = GithubException(403, "Rate limit exceeded")

        integration = GitHubIntegration()

        with pytest.raises(GithubException):
            integration.get_repository("user/repo")

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_invalid_repository_name(self, mock_github, mock_user):
        """Test with invalid repository name format."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.side_effect = GithubException(400, "Bad Request")

        integration = GitHubIntegration()

        with pytest.raises(GithubException):
            integration.get_repository("invalid-name")

    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'test-token'})
    def test_network_error(self, mock_github, mock_user):
        """Test handling of network errors."""
        mock_github.get_user.return_value = mock_user
        mock_github.get_repo.side_effect = Exception("Network error")

        integration = GitHubIntegration()

        with pytest.raises(Exception, match="Network error"):
            integration.get_repository("user/repo")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
