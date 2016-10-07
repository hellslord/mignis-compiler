#! /usr/bin/env python

__author__ = "Alessio Zennaro"


''' The list of supported target languages, imported as classes '''
from netfilter_engine import NetfilterEngine        # Netfilter/Iptables
from example_engine import ExampleEngine            # Example

import os
import shutil
import sys


''' Main function '''
def main():
    # We must have a parameter stating which target language we want
    if len(sys.argv) == 1 or (len(sys.argv) < 3 and sys.argv[1] != "list"):
        print(
            "Usage: ./target_compiler.py [list | <target_language>] <directory>"
        )
        exit(-1)

    # We save the directory we want to work on and we check that the directory
    # name is well-formed
    main_dir = sys.argv[2] if len(sys.argv) > 2 else ""
    if len(main_dir) > 0 and main_dir[len(main_dir) - 1] != '/':
        print("FATAL: <directory> must end with a '/' character")
        exit(-1)

    if main_dir != "":
        try:
            # If <dir>/final already exists, we delete it.
            # We remove it if it is a file or a dir as well
            dir = main_dir + "/final"
            if os.path.isdir(dir):
                shutil.rmtree(dir)
            elif os.path.isfile(dir):
                os.remove(dir)

            # Ok, a new empty directory is created
            os.makedirs(dir)
        except IOError as _:
            # If something goes wrong, kill everything!
            print("FATAL: I/O error")
            exit(-1)

    # Select the engine
    engine = None
    if sys.argv[1] == "IPTABLES":
        engine = NetfilterEngine(main_dir)
    elif sys.argv[1] == "EXAMPLE":
        engine = ExampleEngine(main_dir)
    # Special value: we obtain a list of supported target languages
    elif sys.argv[1] == "list":
        print("List of supported final target languages:")
        print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
        print("\n")
        print("IPTABLES:\tStandard Netfilter/iptables for Linux OS")
        print(
            "EXAMPLE:\tAn example used as test that produces a fake final " + \
            "configuration"
        )
        print("\n")
        exit(0)
    else:  # Unknown language
        print("Unknown language. Type './target_compiler list' for the " + \
              "complete list of supported target languages"
        )
        exit(1)

    # If we arrive here, we're done!
    print("\nComplete! Written %d final configurations" % engine.compile())



''' The entry point of the program is the main() function '''
if __name__ == "__main__":
    main()