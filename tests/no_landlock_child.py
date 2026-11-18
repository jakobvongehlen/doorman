"""A helper worker on a kernel without Landlock, for test_security_isolation.py:
python -m tests.no_landlock_child <worker module> <its arguments>."""

import runpy
import sys

from doorman import sandbox

sandbox.landlock_abi = lambda: 0
module = sys.argv.pop(1)
runpy.run_module(module, run_name="__main__", alter_sys=True)
