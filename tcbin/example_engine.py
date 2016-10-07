__author__ = "Alessio Zennaro"

from generic_engine import GenericEngine


''' This class extends the GenericEngine and can be used as a template class
    for new supported target languages.
    It consists of just two methods: the constructor and the translate method:
     * The constructor is used only to specify the target language we are
       implementing
     * The translate method is the one that actually translate the intermediate
       representation into the final target language. Needless to say, this is
       the method that must perform the most important operations
'''
class ExampleEngine(GenericEngine):

    ''' Constructor method. It just sets the name of the language and the
        directory
    '''
    def __init__(self, directory):
        GenericEngine.__init__(self, directory)
        self.language = "example"  # This is just an example

    ''' translate method. It performs the whole translation from the
        intermediate representation into the target language
    '''
    def translate(self, configuration):
        # Again, this is just an example
        return "This is just an example of final target language!"