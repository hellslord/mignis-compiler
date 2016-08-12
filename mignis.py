#!/usr/bin/env python

__author__ = 'Alessio Zennaro'

import subprocess
import sys
import os

def main():
    if len(sys.argv) < 2:
        print("Usage: ./mignis.py [list | <language>] <file>")
        exit(0)

    if len(sys.argv) == 2 and sys.argv[1] == "list":
        print(subprocess.check_output("./tcbin/target_compiler.py list", shell=True).decode())
        exit(0)
    elif len(sys.argv) == 2 and sys.argv[1] != "list":
        print("Usage: ./mignis.py [list | <language>] <file>")
        exit(0)

    language = sys.argv[1]
    file = sys.argv[2]
    directory = os.path.dirname(file) + "/"

    try:
        print(subprocess.check_output("./utils/mignis_ic -f " + file, shell=True).decode())
        print(subprocess.check_output("./tcbin/target_compiler.py " + language + " " + directory, shell=True).decode())
    except subprocess.CalledProcessError, e:
        print(e.output)

''' The entry point of the program is the main() function '''
if __name__ == "__main__":
    main()