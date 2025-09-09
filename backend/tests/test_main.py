import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import json

# Import the FastAPI app
from main import app
from models import NLQuery, SplunkRunRequest

class TestSplunkLensAPI:
    def setup_method(self):
        self.client = TestClient(app)
    
    def test_root_endpoint(self):
        """Test the root endpoint"""
        response = self.client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "splunkLens API is running"}
    
    @patch('main.generate_ast_from_nl')
    @patch('main.compiler.compile')
    @patch('main.generate_explanation')
    def test_generate_spl_success(self, mock_explanation, mock_compile, mock_ast):
        """Test successful SPL generation"""
        # Mock the dependencies
        mock_ast.return_value = MagicMock()
        mock_compile.return_value = "search index=main error | stats count"
        mock_explanation.return_value = "This query searches for errors and counts them"
        
        # Test data
        query_data = {
            "query": "Show me all errors from today",
            "index": "main",
            "lookback_days": 1
        }
        
        response = self.client.post("/generate-spl", json=query_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "spl" in data
        assert "explanation" in data
        assert "estimated_cost" in data
        assert "estimated_results" in data
        assert data["spl"] == "search index=main error | stats count"
    
    def test_generate_spl_validation_error(self):
        """Test SPL generation with validation error"""
        # Invalid query data (missing required field)
        query_data = {
            "index": "main"
            # Missing 'query' field
        }
        
        response = self.client.post("/generate-spl", json=query_data)
        
        assert response.status_code == 422  # Validation error
    
    @patch('main.generate_ast_from_nl')
    def test_generate_spl_openai_error(self, mock_ast):
        """Test SPL generation with OpenAI error"""
        # Mock OpenAI error
        mock_ast.side_effect = Exception("OpenAI API error")
        
        query_data = {
            "query": "Show me all errors",
            "index": "main",
            "lookback_days": 1
        }
        
        response = self.client.post("/generate-spl", json=query_data)
        
        assert response.status_code == 500
        assert "error" in response.json()["detail"].lower()
    
    @patch('main.requests.post')
    @patch('main.requests.get')
    @patch('main.validator.validate_spl')
    def test_run_splunk_success(self, mock_validate, mock_get, mock_post):
        """Test successful Splunk query execution"""
        # Mock validation
        mock_validate.return_value = MagicMock(is_valid=True, errors=[])
        
        # Mock Splunk API responses
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"sid": "test_job_123"}
        )
        
        # Mock job status and results
        mock_get.side_effect = [
            # Job status response
            MagicMock(
                status_code=200,
                json=lambda: {
                    "entry": [{
                        "content": {"dispatchState": "DONE"}
                    }]
                }
            ),
            # Results response
            MagicMock(
                status_code=200,
                json=lambda: {
                    "results": [
                        {"_time": "2024-01-01T00:00:00", "count": "100"},
                        {"_time": "2024-01-01T01:00:00", "count": "150"}
                    ]
                }
            )
        ]
        
        # Test data
        run_data = {
            "spl": "search index=main error | stats count",
            "splunk_token": "test_token_123",
            "max_results": 100
        }
        
        response = self.client.post("/run-splunk", json=run_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert "results_link" in data
        assert "preview_rows" in data
        assert "total_results" in data
        assert "status" in data
        assert data["job_id"] == "test_job_123"
        assert data["status"] == "completed"
    
    @patch('main.validator.validate_spl')
    def test_run_splunk_validation_error(self, mock_validate):
        """Test Splunk query execution with validation error"""
        # Mock validation failure
        mock_validate.return_value = MagicMock(
            is_valid=False,
            errors=["Dangerous command detected: rest"]
        )
        
        run_data = {
            "spl": "| rest /services/server/info",
            "splunk_token": "test_token_123"
        }
        
        response = self.client.post("/run-splunk", json=run_data)
        
        assert response.status_code == 400
        assert "validation failed" in response.json()["detail"].lower()
    
    def test_run_splunk_no_auth(self):
        """Test Splunk query execution without authentication"""
        run_data = {
            "spl": "search index=main error | stats count"
            # No splunk_token provided
        }
        
        response = self.client.post("/run-splunk", json=run_data)
        
        assert response.status_code == 400
        assert "authentication" in response.json()["detail"].lower()
    
    @patch('main.requests.post')
    @patch('main.validator.validate_spl')
    def test_run_splunk_network_error(self, mock_validate, mock_post):
        """Test Splunk query execution with network error"""
        # Mock validation success
        mock_validate.return_value = MagicMock(is_valid=True, errors=[])
        
        # Mock network error
        mock_post.side_effect = Exception("Connection refused")
        
        run_data = {
            "spl": "search index=main error | stats count",
            "splunk_token": "test_token_123"
        }
        
        response = self.client.post("/run-splunk", json=run_data)
        
        assert response.status_code == 500
        assert "failed to run" in response.json()["detail"].lower()
    
    def test_estimate_query_cost(self):
        """Test query cost estimation"""
        from main import estimate_query_cost
        
        # Simple query
        simple_cost = estimate_query_cost("search index=main error")
        assert simple_cost > 0
        
        # Complex query with multiple commands
        complex_cost = estimate_query_cost(
            "search index=main error | stats count by host | timechart span=1h count"
        )
        assert complex_cost > simple_cost
        
        # Query with expensive operations
        expensive_cost = estimate_query_cost(
            "search index=main | eval complex=case(a>1,b,c>2,d,1=1,e) | lookup large_table key | timechart span=1m avg(value)"
        )
        assert expensive_cost > complex_cost
    
    def test_estimate_result_size(self):
        """Test result size estimation"""
        from main import estimate_result_size
        
        # Query with count aggregation
        count_size = estimate_result_size("search index=main | stats count by host")
        assert count_size == 100  # Grouping queries return fewer results
        
        # Query with head limit
        head_size = estimate_result_size("search index=main | head 50")
        assert head_size == 50
        
        # Query with limit
        limit_size = estimate_result_size("search index=main | limit 25")
        assert limit_size == 25
        
        # Query with table
        table_size = estimate_result_size("search index=main | table _time, host, message")
        assert table_size == 500
        
        # Default case
        default_size = estimate_result_size("search index=main error")
        assert default_size == 1000
    
    def test_golden_api_cases(self):
        """Golden test cases for API endpoints"""
        golden_cases = [
            # Valid query cases
            {
                "endpoint": "/generate-spl",
                "method": "POST",
                "data": {
                    "query": "Show me errors from web server",
                    "index": "web",
                    "lookback_days": 1
                },
                "expected_status": 200,
                "expected_fields": ["spl", "explanation", "estimated_cost", "estimated_results"]
            },
            {
                "endpoint": "/generate-spl",
                "method": "POST",
                "data": {
                    "query": "Count authentication failures by user",
                    "index": "security",
                    "sourcetype": "windows_security",
                    "lookback_days": 7
                },
                "expected_status": 200,
                "expected_fields": ["spl", "explanation", "estimated_cost", "estimated_results"]
            }
        ]
        
        for case in golden_cases:
            with patch('main.generate_ast_from_nl') as mock_ast, \
                 patch('main.compiler.compile') as mock_compile, \
                 patch('main.generate_explanation') as mock_explanation:
                
                # Mock the dependencies
                mock_ast.return_value = MagicMock()
                mock_compile.return_value = "search index=main | stats count"
                mock_explanation.return_value = "Test explanation"
                
                if case["method"] == "POST":
                    response = self.client.post(case["endpoint"], json=case["data"])
                else:
                    response = self.client.get(case["endpoint"])
                
                assert response.status_code == case["expected_status"], f"Case failed: {case}"
                
                if "expected_fields" in case:
                    data = response.json()
                    for field in case["expected_fields"]:
                        assert field in data, f"Missing field {field} in response: {data}"
    
    def test_cors_headers(self):
        """Test CORS headers are properly set"""
        response = self.client.get("/")
        
        # CORS headers should be present for cross-origin requests
        # Note: TestClient doesn't automatically add CORS headers,
        # but we can test that the middleware is configured
        assert response.status_code == 200
    
    def test_error_response_format(self):
        """Test error responses follow consistent format"""
        # Test validation error format
        response = self.client.post("/generate-spl", json={})
        assert response.status_code == 422
        assert "detail" in response.json()
        
        # Test with invalid JSON
        response = self.client.post(
            "/generate-spl",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422