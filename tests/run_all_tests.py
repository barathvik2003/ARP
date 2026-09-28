"""
MASTER TEST RUNNER
Runs all tests in sequence.
Run: python tests/run_all_tests.py
"""
import sys, os, time
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

TESTS = [
    ("01_test_connection.py", "Connection Test"),
    ("02_test_collect.py", "Data Collection Test"),
    ("03_test_detect.py", "Detection Engine Test"),
    ("04_test_remediate.py", "Remediation Test"),
    ("05_test_web_console.py", "Web Console API Test"),
    ("06_test_attack_sim.py", "Attack Simulation Test"),
    ("07_test_block_verify.py", "Advanced Blocking Test"),
]

def run_test(filename, name):
    print(f"\n{'#' * 60}")
    print(f"  RUNNING: {name}")
    print(f"  File: tests/{filename}")
    print(f"{'#' * 60}\n")

    filepath = os.path.join(os.path.dirname(__file__), filename)
    try:
        spec = importlib.util.spec_from_file_location(f"test_{filename}", filepath)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Try test_ functions first
        test_func_name = filename.replace(".py", "")
        for attr_name in dir(module):
            if attr_name.startswith("test_"):
                func = getattr(module, attr_name)
                if callable(func):
                    result = func()
                    return result

        # Fallback: run main() if defined
        if hasattr(module, "main"):
            module.main()
            return True
    except Exception as e:
        print(f"  [ERROR] {name} failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("  ARP DETECTION SYSTEM - FULL TEST SUITE")
    print("=" * 60)
    print(f"  Running {len(TESTS)} tests...")
    print(f"  Target: RHEL server via SSH")

    results = {}
    start_time = time.time()

    for filename, name in TESTS:
        try:
            result = run_test(filename, name)
            results[name] = result
        except Exception as e:
            print(f"  [ERROR] {name}: {e}")
            results[name] = False

    elapsed = time.time() - start_time

    print("\n" + "=" * 60)
    print("  TEST RESULTS SUMMARY")
    print("=" * 60)

    passed = 0
    failed = 0
    for name, result in results.items():
        status = "PASS" if result else "FAIL"
        icon = "[OK]" if result else "[!!]"
        print(f"  {icon} {name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n  Total: {len(results)} | Passed: {passed} | Failed: {failed}")
    print(f"  Time: {elapsed:.1f}s")

    if failed == 0:
        print("\n  ALL TESTS PASSED!")
    else:
        print(f"\n  {failed} test(s) failed. Check output above.")

    return failed == 0

if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
