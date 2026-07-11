import sys
from pathlib import Path

# Make `policy_utils` importable when pytest is invoked from any cwd.
sys.path.insert(0, str(Path(__file__).resolve().parent))
