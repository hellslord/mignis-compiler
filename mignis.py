#!/usr/bin/env python

__author__ = 'Alessio Zennaro'

import subprocess
import sys
import os


''' The main function '''
def main():
    if len(sys.argv) < 2:  # This is how the file must be used
        print("Usage: ./mignis.py [list | <language>] <file>")
        exit(0)

    if len(sys.argv) == 2 and sys.argv[1] == "list":  # Show a list of supported language
        print(subprocess.check_output("./tcbin/target_compiler.py list", shell=True).decode())
        exit(0)
    elif len(sys.argv) == 2 and sys.argv[1] != "list":  # This is a wrong usage
        print("Usage: ./mignis.py [list | <language>] <file>")
        exit(0)

    language = sys.argv[1]  # The language to be used
    file_name = sys.argv[2]  # The complete file name
    directory = os.path.dirname(file_name) + "/"  # The directory the file is located in
    if directory == "/":  # If there's no directory
        directory = '.' + directory  # Add it as the local one

    # Try to execute the compiler and the translator
    try:
        print(subprocess.check_output("./utils/mignis_ic -f " + file_name, shell=True).decode())
        print(subprocess.check_output("./tcbin/target_compiler.py " + language + " " + directory, shell=True).decode())
    except subprocess.CalledProcessError, e:
        print(e.output)

''' The entry point of the program is the main() function '''
if __name__ == "__main__":
    main()