"""Runs the conformance tests: python3 tests/run_tests.py [unittest args]

BSERVE and BCURL name the binaries under test (default: the sanitizer build
in build/debug/). FUZZ_SEED fixes the fuzz tests' random seed.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import harness  # noqa: E402


def main():
    for path in (harness.BSERVE, harness.BCURL):
        if not os.access(path, os.X_OK):
            sys.exit("missing %s: run `make debug` first" % path)
    print("bserve: %s\nbcurl:  %s" % (harness.BSERVE, harness.BCURL))
    loader = unittest.defaultTestLoader
    if len(sys.argv) > 1:
        suite = loader.loadTestsFromNames(sys.argv[1:])
    else:
        suite = loader.discover(HERE, pattern="test_*.py", top_level_dir=HERE)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
