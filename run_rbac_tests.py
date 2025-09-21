#!/usr/bin/env python3
"""
RBAC Test Runner

Specialized test runner for RBAC functionality with detailed reporting.
"""

import subprocess
import sys
from pathlib import Path


def run_rbac_tests():
    """Run RBAC-specific tests with detailed output"""

    print("Running RBAC System Tests")
    print("=" * 50)

    # Change to the API directory
    api_dir = Path(__file__).parent

    # Run RBAC tests with specific markers
    test_commands = [
        # Unit tests for RBAC
        [
            "python", "-m", "pytest",
            "tests/test_rbac.py",
            "-m", "unit and rbac",
            "-v", "--tb=short",
            "--cov=app.rbac",
            "--cov-report=term-missing"
        ],

        # Integration tests for RBAC
        [
            "python", "-m", "pytest",
            "tests/test_rbac.py",
            "-m", "integration and rbac",
            "-v", "--tb=short"
        ],

        # Security tests for RBAC
        [
            "python", "-m", "pytest",
            "tests/test_rbac.py",
            "-m", "security and rbac",
            "-v", "--tb=short"
        ]
    ]

    for i, cmd in enumerate(test_commands, 1):
        print(f"\nRunning Test Suite {i}/{len(test_commands)}")
        print(f"Command: {' '.join(cmd)}")
        print("-" * 40)

        try:
            result = subprocess.run(
                cmd,
                cwd=api_dir,
                capture_output=False,
                text=True
            )

            if result.returncode != 0:
                print(f"[FAIL] Test suite {i} failed with return code {result.returncode}")
                return False
            else:
                print(f"[PASS] Test suite {i} passed")

        except Exception as e:
            print(f"[ERROR] Error running test suite {i}: {e}")
            return False

    print("\nAll RBAC tests completed successfully!")
    return True


def check_dependencies():
    """Check if required test dependencies are installed"""
    required_packages = [
        'pytest',
        'pytest-asyncio',
        'pytest-cov',
        'pytest-mock'
    ]

    missing = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)

    if missing:
        print(f"[ERROR] Missing required packages: {', '.join(missing)}")
        print("Install with: pip install " + " ".join(missing))
        return False

    return True


def main():
    """Main function"""
    print("Checking dependencies...")

    if not check_dependencies():
        sys.exit(1)

    print("[OK] Dependencies OK")

    success = run_rbac_tests()

    if not success:
        sys.exit(1)

    print("\nRBAC test suite completed successfully!")


if __name__ == "__main__":
    main()