
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



# inspired from stackoverflow
# http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python/377028
def which(program, extra_paths = None):
    "extra path is a string containing a list of path separated by : which "

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        tmp = []
        if extra_paths :
            tmp = extra_paths.split(":")
        for path in os.environ["PATH"].split(os.pathsep) + tmp:
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None


def getLDLibraryPath(env):
    """given a list of environment variables it return a list of
    absolute path defined in LD_LIBRARY_PATH (if a path is relative
    it will be transformed in an absolute with PWD)"""

    ld_library_paths = []
    if env:
        for var in env:
            if var.startswith('LD_LIBRARY_PATH='):
                ld_library_paths = var.split('=')[1].split(':')
                break
        #now find PWD
        pwd = [var.split('=')[1] for var in env if var.startswith('PWD=')]
        if len(pwd) != 1:
            #logger.error("Unable to find PWD in traced process environment variables")
            pwd = os.environ['PWD']
        else:
            pwd = pwd[0]
        # make ld_library_paths_path abolute path
        temp = []
        for path in ld_library_paths:
            if path.startswith('/'):
                temp.append(path)
            else:
                temp.append(os.path.normpath(os.path.join(pwd, path)))
        ld_library_paths = temp
    return ld_library_paths


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
