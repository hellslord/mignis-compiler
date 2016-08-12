__author__ = "Alessio Zennaro"

from abc import ABCMeta, abstractmethod
import os
import itertools

''' This class is used as a model for all target languages.
    Basically it is an abstract class that is able to read all the files written in the
    intermediate representation and, from those files, it produces the final form in the
    target language. Since this is a generic model, the translation into the final language
    is kept abstract
'''
class GenericEngine:
    __metaclass__ = ABCMeta

    ''' Following there are variables that represent the keywords of the intermediate
        language. These are useful in order to avoid to use direct strings in the code
    '''
    OPTN = "OPTN"
    BIND = "BIND"
    ALLW = "ALLW"
    DROP = "DROP"
    RJCT = "RJCT"
    TALW = "TALW"
    PDRP = "PDRP"
    PRJC = "PRJC"
    CSTM = "CSTM"

    LOCAL = "LOCAL"
    ANY = "ANY"
    MASQUERADE = "MASQUERADE"

    ''' This method just inits the language property '''
    def __init__(self, directory):
        self.language = ""
        self.directory = directory


    ''' This method is used to actually read all the intermediate representations and then
        translate them into the final target language via the translate method.
        The ../final folder is supposed to already exist.
        The files inside the ../final folder are in the form fw<index>.<target_language>
        If an IOErr occurs, the current file is skipped.
        It returns the number of final configurations written to disk
    '''
    def compile(self):
        # The complete file name structure is ../final/fw<index>.<targe_language>
        prefix = self.directory + "final/fw"
        suffix = "." + self.language

        # We get all the configurations written in the intermediate representation
        conf_list = self.read_files()

        n = 0
        # For all the configurations found
        for conf in conf_list:
            final_conf = self.translate(conf) # Translate it
            file_name = prefix + str(n) + suffix # Create the file name
            try:
                # Create a new file and write the final configuration in it
                out_stream = open(file_name, "w")
                out_stream.write(final_conf)
                out_stream.flush()
                out_stream.close()
                n += 1
            except IOError as _:
                # If something goes wrong, skip the file and continue with the next
                print("ERR: Skipping output file %s because of an I/O error" % file_name)
                continue

        # Return the number of final configurations written
        return n


    ''' This method is used to read all the configuration files
        written in the intermediate mignis representation.
        Files must be in the ../compiled folder and file names must
        be in the form fw<index>.config.
        If a file is not readable then it is skipped.
        If a file does not exist, the procedure terminates
    '''
    def read_files(self):
        # The complete file name structure is ../compiled/fw<index>.config
        prefix = self.directory + "compiled/fw"
        suffix = ".config"

        # The returned list is made of strings and each string is a configuration
        conf_list = []
        total = 0

        # Forever...
        for i in itertools.count():
            file_name = prefix + str(i) + suffix # The complete name is built
            if os.path.isfile(file_name): # Does the file exist?
                try:
                    # If it exists (and it is readable): open it, read it and close it
                    in_stream = open(file_name, "r")
                    conf_list.append(in_stream.read()) # Add the content to the list
                    in_stream.close()
                    total += 1
                except IOError as _:
                    # If it exists but something goes wrong: skip it and inform user
                    print("ERR: Skipping input file %s since it isn't readable" % file_name)
            else:
                # If it doesn't exist: break the loop
                break

        # Inform the user of the number of configurations successfully read and return the list
        print("\nINF: Successfully read %d files\n" % total)
        return conf_list

    ''' This method is used to parse a line. A line is made of a string, a colon and then another string
        made of a sequence of string separated by a semicolon.
        It returns a tuple of two elements: the first one is the first string, the second one is a list of all
        the parameters found in the second string
    '''
    def parse_line(self, line):
        cmd_par = line.split(':')
        par_list = cmd_par[1].split(';')

        return (cmd_par[0], par_list)

    ''' This method is used to get all the details of a rule, grouped by their meaning. For instance the first
        three elements are to identify the source endpoint, so they are grouped together (host, int, port).
        We are sure that all these elements exist because the intermediate representation gives all the infos
        even if they are empty.
    '''
    def get_rule_details(self, par):
        if len(par) != 14:  # Here something is wrong, not a rule
            print("ERR: bad parameter")
            exit(-1)  # We must exit, unrecoverable error!

        source = (par[0], par[1], par[2])  # source endpoint: (host, interface, port)
        snat = (par[3], par[4], par[5])  # sNAT: from a syntactic POV is an endpoint
        destination = (par[6], par[7], par[8])  # destination endpoint
        dnat = (par[9], par[10], par[11])  # dNAT
        protocol = par[12]  # protocol
        formula = par[13]  # custom rules

        # Return a list with all these infos in tuples
        return [source, snat, destination, dnat, protocol, formula]

    ''' This method is used to modify a string in order to change a parameter. This is particularly
        useful when the two way allow operator (<>) is used: for instance the source port in one
        rule becomes the destination port in the twin rule. By simply using this method with the
        correct parameters, the task of updating the rule is very easy
    '''
    def switch_elements(self, string, pattern_list):
        return_string = string
        for pattern in pattern_list:
            return_string = return_string.replace(pattern[0], pattern[1])

        return return_string

    ''' This abstract method is the very heart of the whole program. It takes
        a cofiguration written in intermediate representation and it translates it into
        a configuration written in the target language.
    '''
    @abstractmethod
    def translate(self, configuration): pass