"""``python -m avra.runner [--check]`` — start (or just validate) the Tool
Runner. Runs on the Kali VM only."""

import sys

from avra.runner.server import main

sys.exit(main(argv=sys.argv[1:]))
