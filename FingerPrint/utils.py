
from subprocess import PIPE, Popen
import subprocess

def getOutputAsList(binary, inputString=None):
    """ run popen pipe inputString and return the output 
    as a list of string one for each line
    """
    p = Popen(binary, stdin=PIPE, stdout=PIPE)
    grep_stdout = p.communicate(input=inputString)[0]
    return grep_stdout.split('\n')


def which(program, extraPath):

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep) + extraPath:
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None

