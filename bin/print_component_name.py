#!/usr/bin/env python3
"""Print the component name of an artifact: its image name, which tells apart artifacts built by one repo."""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from artifacts import component_name  # noqa: E402

_EXAMPLE = """
example:

  bin/print_component_name.py 244531986313.dkr.ecr.eu-central-1.amazonaws.com/creator:9c517d0
  creator
"""


def main(argv):
    """Print the component name of the artifact named on the command line."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("artifact_name",
                        help="The artifact's image name, eg <registry>/<image>:<tag>")
    args = parser.parse_args(argv)
    print(component_name(args.artifact_name))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
