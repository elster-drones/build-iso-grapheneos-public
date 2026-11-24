import sys
from pathlib import Path

# build.py imports fdroid.py from the adapter root, as it does when run as ./build.sh.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
