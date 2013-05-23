
from subprocess import PIPE, Popen
import subprocess
import os

def getOutputAsList(binary, inputString=None):
    """ run popen pipe inputString and return a touple of
    (the stdout as a list of string, return value of the command)
    """
    p = Popen(binary, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    grep_stdout = p.communicate(input=inputString)[0]
    p.wait()
    return (grep_stdout.split('\n'), p.returncode)



# copied from stackoverflow
# http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python/377028
def which(program):

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None


def any(iterable):
    for element in iterable:
        if element:
            return True
    return False

def all(iterable):
    for element in iterable:
        if not element:
            return False
    return True
