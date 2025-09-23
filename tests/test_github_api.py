import pytest
import os
from unittest.mock import Mock, patch
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from threat_radar.core.github_integration import GitHubIntegration


class TestGitHubIntegration:
    def test_init_with_token(self):
        with patch('threat_radar.core.github_integration.Github') as mock_github:
            mock_instance = Mock()
            mock_github.return_value = mock_instance
            mock_instance.get_user.return_value = Mock()
            
            client = GitHubIntegration("test_token")
            assert client.token == "test_token"
            mock_github.assert_called_once_with("test_token")
    
    def test_init_without_token_raises_error(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="GitHub access token is required"):
                GitHubIntegration()
    
    @patch.dict(os.environ, {'GITHUB_ACCESS_TOKEN': 'env_token'})
    def test_init_with_env_token(self):
        with patch('threat_radar.core.github_integration.Github') as mock_github:
            mock_instance = Mock()
            mock_github.return_value = mock_instance
            mock_instance.get_user.return_value = Mock()
            
            client = GitHubIntegration()
            assert client.token == "env_token"
    
    def test_get_repository(self):
        with patch('threat_radar.core.github_integration.Github') as mock_github:
            mock_instance = Mock()
            mock_github.return_value = mock_instance
            mock_instance.get_user.return_value = Mock()
            mock_repo = Mock()
            mock_instance.get_repo.return_value = mock_repo
            
            client = GitHubIntegration("test_token")
            repo = client.get_repository("test/repo")
            
            mock_instance.get_repo.assert_called_once_with("test/repo")
            assert repo == mock_repo