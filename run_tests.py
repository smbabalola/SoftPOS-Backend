#!/usr/bin/env python3
"""
SoftPOS Test Runner

Comprehensive test runner for the SoftPOS API with different test categories,
coverage reporting, and CI/CD integration.

Usage:
    python run_tests.py                 # Run all tests
    python run_tests.py --unit          # Run only unit tests
    python run_tests.py --integration   # Run only integration tests
    python run_tests.py --security      # Run only security tests
    python run_tests.py --coverage      # Run with detailed coverage report
    python run_tests.py --ci            # CI mode (no interactive output)
"""

import argparse
import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

import pytest


class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


class TestRunner:
    """Main test runner class."""

    def __init__(self, ci_mode: bool = False):
        self.ci_mode = ci_mode
        self.start_time = time.time()
        self.results = {}

    def print_header(self):
        """Print test runner header."""
        if not self.ci_mode:
            print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.BLUE}SoftPOS API Test Suite{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    def print_section(self, title: str):
        """Print section header."""
        if not self.ci_mode:
            print(f"\n{Colors.BOLD}{Colors.CYAN}* {title}{Colors.RESET}")
            print(f"{Colors.CYAN}{'-'*50}{Colors.RESET}")

    def print_success(self, message: str):
        """Print success message."""
        print(f"{Colors.GREEN}[PASS] {message}{Colors.RESET}")

    def print_warning(self, message: str):
        """Print warning message."""
        print(f"{Colors.YELLOW}[WARN] {message}{Colors.RESET}")

    def print_error(self, message: str):
        """Print error message."""
        print(f"{Colors.RED}[FAIL] {message}{Colors.RESET}")

    def print_info(self, message: str):
        """Print info message."""
        print(f"{Colors.BLUE}[INFO] {message}{Colors.RESET}")

    def check_dependencies(self) -> bool:
        """Check if all required dependencies are installed."""
        self.print_section("Checking Dependencies")

        required_packages = [
            'pytest',
            'pytest-asyncio',
            'pytest-cov',
            'pytest-mock',
            'httpx',
            'fastapi',
            'sqlalchemy',
            'redis'
        ]

        missing_packages = []

        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
                self.print_success(f"{package} is installed")
            except ImportError:
                missing_packages.append(package)
                self.print_error(f"{package} is missing")

        if missing_packages:
            self.print_error(f"Missing packages: {', '.join(missing_packages)}")
            self.print_info("Install missing packages with: poetry install")
            return False

        return True

    def check_environment(self) -> bool:
        """Check test environment setup."""
        self.print_section("Checking Environment")

        # Check if we're in the correct directory
        if not Path("app").exists():
            self.print_error("app/ directory not found. Run from API root directory.")
            return False

        # Check test directory
        if not Path("tests").exists():
            self.print_error("tests/ directory not found.")
            return False

        # Set testing environment variables
        os.environ["TESTING"] = "true"
        os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
        os.environ["REDIS_URL"] = "redis://localhost:6379/15"

        self.print_success("Environment setup complete")
        return True

    def run_linting(self) -> bool:
        """Run code linting."""
        self.print_section("Running Code Linting")

        try:
            # Run ruff linting
            result = subprocess.run(
                ["ruff", "check", "app/", "tests/"],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                self.print_success("Linting passed")
                return True
            else:
                self.print_error("Linting failed")
                if not self.ci_mode:
                    print(result.stdout)
                    print(result.stderr)
                return False

        except subprocess.TimeoutExpired:
            self.print_error("Linting timed out")
            return False
        except FileNotFoundError:
            self.print_warning("Ruff not found, skipping linting")
            return True

    def run_pytest(
        self,
        markers: Optional[List[str]] = None,
        coverage: bool = False,
        verbose: bool = True
    ) -> bool:
        """Run pytest with specified parameters."""
        cmd = ["python", "-m", "pytest"]

        # Add markers
        if markers:
            for marker in markers:
                cmd.extend(["-m", marker])

        # Add coverage
        if coverage:
            cmd.extend([
                "--cov=app",
                "--cov-report=term-missing",
                "--cov-report=html:htmlcov",
                "--cov-fail-under=80"
            ])

        # Add verbosity
        if verbose and not self.ci_mode:
            cmd.append("-v")
        elif self.ci_mode:
            cmd.append("-q")

        # Add other options
        cmd.extend([
            "--tb=short",
            "--strict-markers",
            "--disable-warnings"
        ])

        try:
            result = subprocess.run(cmd, timeout=600)  # 10 minute timeout
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            self.print_error("Tests timed out after 10 minutes")
            return False

    def run_unit_tests(self) -> bool:
        """Run unit tests."""
        self.print_section("Running Unit Tests")
        success = self.run_pytest(markers=["unit"])
        self.results["unit"] = success
        return success

    def run_integration_tests(self) -> bool:
        """Run integration tests."""
        self.print_section("Running Integration Tests")
        success = self.run_pytest(markers=["integration"])
        self.results["integration"] = success
        return success

    def run_security_tests(self) -> bool:
        """Run security tests."""
        self.print_section("Running Security Tests")
        success = self.run_pytest(markers=["security"])
        self.results["security"] = success
        return success

    def run_payment_tests(self) -> bool:
        """Run payment-specific tests."""
        self.print_section("Running Payment Tests")
        success = self.run_pytest(markers=["payment"])
        self.results["payment"] = success
        return success

    def run_terminal_tests(self) -> bool:
        """Run terminal management tests."""
        self.print_section("Running Terminal Management Tests")
        success = self.run_pytest(markers=["terminal"])
        self.results["terminal"] = success
        return success

    def run_webhook_tests(self) -> bool:
        """Run webhook tests."""
        self.print_section("Running Webhook Tests")
        success = self.run_pytest(markers=["webhook"])
        self.results["webhook"] = success
        return success

    def run_monitoring_tests(self) -> bool:
        """Run monitoring tests."""
        self.print_section("Running Monitoring Tests")
        success = self.run_pytest(markers=["monitoring"])
        self.results["monitoring"] = success
        return success

    def run_fraud_tests(self) -> bool:
        """Run fraud detection tests."""
        self.print_section("Running Fraud Detection Tests")
        success = self.run_pytest(markers=["fraud"])
        self.results["fraud"] = success
        return success

    def run_e2e_tests(self) -> bool:
        """Run end-to-end tests."""
        self.print_section("Running End-to-End Tests")
        success = self.run_pytest(markers=["e2e"])
        self.results["e2e"] = success
        return success

    def run_slow_tests(self) -> bool:
        """Run slow tests."""
        self.print_section("Running Slow Tests")
        success = self.run_pytest(markers=["slow"])
        self.results["slow"] = success
        return success

    def run_coverage_tests(self) -> bool:
        """Run all tests with coverage."""
        self.print_section("Running Tests with Coverage")
        success = self.run_pytest(coverage=True)
        self.results["coverage"] = success

        if success and not self.ci_mode:
            self.print_info("Coverage report generated in htmlcov/index.html")

        return success

    def run_all_tests(self) -> bool:
        """Run all test categories."""
        self.print_section("Running All Tests")
        success = self.run_pytest()
        self.results["all"] = success
        return success

    def print_summary(self):
        """Print test run summary."""
        end_time = time.time()
        duration = end_time - self.start_time

        if not self.ci_mode:
            print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.BLUE}Test Summary{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")

        total_success = all(self.results.values())

        for test_type, success in self.results.items():
            if success:
                self.print_success(f"{test_type.replace('_', ' ').title()} tests passed")
            else:
                self.print_error(f"{test_type.replace('_', ' ').title()} tests failed")

        print(f"\n{Colors.BOLD}Total duration: {duration:.2f} seconds{Colors.RESET}")

        if total_success:
            print(f"\n{Colors.BOLD}{Colors.GREEN}All tests passed!{Colors.RESET}")
            return True
        else:
            print(f"\n{Colors.BOLD}{Colors.RED}Some tests failed!{Colors.RESET}")
            return False


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="SoftPOS API Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Test category options
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests only")
    parser.add_argument("--security", action="store_true", help="Run security tests only")
    parser.add_argument("--payment", action="store_true", help="Run payment tests only")
    parser.add_argument("--terminal", action="store_true", help="Run terminal tests only")
    parser.add_argument("--webhook", action="store_true", help="Run webhook tests only")
    parser.add_argument("--monitoring", action="store_true", help="Run monitoring tests only")
    parser.add_argument("--fraud", action="store_true", help="Run fraud detection tests only")
    parser.add_argument("--e2e", action="store_true", help="Run end-to-end tests only")
    parser.add_argument("--slow", action="store_true", help="Run slow tests only")

    # Options
    parser.add_argument("--coverage", action="store_true", help="Run with coverage report")
    parser.add_argument("--ci", action="store_true", help="CI mode (minimal output)")
    parser.add_argument("--no-lint", action="store_true", help="Skip linting")

    args = parser.parse_args()

    # Create test runner
    runner = TestRunner(ci_mode=args.ci)
    runner.print_header()

    # Check dependencies and environment
    if not runner.check_dependencies():
        sys.exit(1)

    if not runner.check_environment():
        sys.exit(1)

    # Run linting unless skipped
    if not args.no_lint:
        if not runner.run_linting():
            if args.ci:
                sys.exit(1)
            else:
                runner.print_warning("Linting failed, but continuing with tests")

    # Determine which tests to run
    test_functions = []

    if args.unit:
        test_functions.append(runner.run_unit_tests)
    elif args.integration:
        test_functions.append(runner.run_integration_tests)
    elif args.security:
        test_functions.append(runner.run_security_tests)
    elif args.payment:
        test_functions.append(runner.run_payment_tests)
    elif args.terminal:
        test_functions.append(runner.run_terminal_tests)
    elif args.webhook:
        test_functions.append(runner.run_webhook_tests)
    elif args.monitoring:
        test_functions.append(runner.run_monitoring_tests)
    elif args.fraud:
        test_functions.append(runner.run_fraud_tests)
    elif args.e2e:
        test_functions.append(runner.run_e2e_tests)
    elif args.slow:
        test_functions.append(runner.run_slow_tests)
    elif args.coverage:
        test_functions.append(runner.run_coverage_tests)
    else:
        # Run all tests
        test_functions.append(runner.run_all_tests)

    # Execute tests
    overall_success = True
    for test_func in test_functions:
        success = test_func()
        overall_success &= success

        # Stop on first failure in CI mode
        if not success and args.ci:
            break

    # Print summary
    runner.print_summary()

    # Exit with appropriate code
    sys.exit(0 if overall_success else 1)


if __name__ == "__main__":
    main()