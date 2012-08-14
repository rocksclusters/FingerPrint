
from subprocess import PIPE, Popen
import subprocess

def getOutputAsList(binary, inputString=None):
    """ run popen pipe inputString and return the output 
    as a list of string one for each line
    """
    p = Popen(binary, stdin=PIPE, stdout=PIPE)
    grep_stdout = p.communicate(input=inputString)[0]
    return grep_stdout.split('\n')

