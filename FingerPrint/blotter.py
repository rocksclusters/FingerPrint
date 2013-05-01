#!/usr/bin/python
#
# LC
#
# This class create swirl starting from binaries, command lines, 
# or process number
#

from datetime import datetime
import subprocess
import os
#TODO remove shlex for python 2.4
import shlex

#
# compatibility with python2.4
#
try:
    from hashlib import md5
except ImportError:
    from md5 import md5

#
# compatibility with python2.4
#
if "any" not in dir(__builtins__):
    from FingerPrint.utils import any

from swirl import Swirl, SwirlFile
import sergeant
from FingerPrint.plugins import PluginManager
from FingerPrint.utils import getOutputAsList


def getDependecyFromPID(pid, dynamicDependecies):
    """ given a pid it scan the procfs to find its loaded dependencies
    and places the output in dynamic depenedencies"""
    binaryFile = os.readlink('/proc/' + pid + '/exe')
    if binaryFile not in dynamicDependecies:
        # new binary file let's add it to the dyctionary
        dynamicDependecies[binaryFile] = []
    f=open('/proc/' + pid + '/maps')
    maps = f.read()
    f.close()
    for i in maps.split('\n'):
        tokens = i.split()
        if len(tokens) > 5 and 'x' in tokens[1] and os.path.isfile(tokens[5]):
            # assumption: if we have a memory mapped area to a file and it is
            # executable then it is a shared library
            libPath = tokens[5].strip()
            if libPath not in dynamicDependecies[binaryFile] and libPath != binaryFile:
                dynamicDependecies[binaryFile].append( libPath )


class Blotter:
    """
    This class creates a swirl file starting from:
     - a list of binaries
     - command lines that we want to execute and trace
     - a list of pids
    """

    def __init__(self, name, fileList, processIDs, execCmd):
        """give a file list and a name construct a swirl into memory """
        self._detectedPackageManager() 
        self.swirl = Swirl(name, datetime.now())
        if execCmd :
            self.swirl.cmdLine = execCmd
        # 
        # dependencies discovered with dinamic methods
        # dynamicDependencies = { 'binarypath' : [list of file it depends to],
        # '/bin/bash' : ['/lib/x86_64-linux-gnu/libnss_files-2.15.so',
        # '/lib/x86_64-linux-gnu/libnss_nis-2.15.so']}
        dynamicDependecies = {}
        files = {}

        if execCmd :
            self._straceCmd(execCmd, dynamicDependecies, files)

        # let's see if we have proecss ID we might need to scan for dynamic dependecies
        # with the help of the /proc FS
        elif processIDs :
            for proc in processIDs.split(','):
                pid = proc.strip()
                # add the binary
                getDependecyFromPID(pid, dynamicDependecies)

        # set up the fileList for the static dependency detection
        if not fileList :
            fileList = []
        fileList = fileList + dynamicDependecies.keys()
        # add all the fileList to the swirl and figure out all their static libraries
        for i in fileList:
            if os.path.isfile(i):
                swirlFile = PluginManager.getSwirl(i, self.swirl)
                self.swirl.execedFiles.append(swirlFile)
            elif os.path.isdir(i):
                pass
            else:
                raise IOError("The file %s cannot be opened." % i)
        #
        # we might need to add the dynamic dependencies to the swirl
        # if they did not get detected already
        for fileName in dynamicDependecies.keys():
            swirlFile = PluginManager.getSwirl(fileName, self.swirl)
            #let's add it to the execed file list
            if swirlFile not in self.swirl.execedFiles:
                self.swirl.execedFile.append(swirlFile)
            for dynamicDepFile in dynamicDependecies[fileName]:
                newSwirlFileDependency = PluginManager.getSwirl(dynamicDepFile, self.swirl)
                #I need to verify it if is static dep or dynamic dep
                #TODO need to optimize this
                swirlDependencies = self.swirl.getListSwirlFilesDependentStatic( swirlFile )
                if newSwirlFileDependency.path not in [x.path for x in swirlDependencies]:
                    swirlFile.dynamicDependencies.append(newSwirlFileDependency)

        # let's see if it used some Data files
        # excludeFileName: file whcih should be ingored and not added to the swirl
        excludeFileName = ['/etc/ld.so.cache']
        for execFile in files:
            swirlFile = self.swirl.createSwirlFile(execFile)
            if swirlFile.isLoader() :
                continue
            allFiles=[]
            #TODO take this for loop out of the for execFile loop
            for deps in self.swirl.getListSwirlFilesDependentStaticAndDynamic(swirlFile):
                allFiles += deps.getPaths()
            for openedFile in files[execFile]:
                if openedFile not in excludeFileName:
                    swirlOpenedFile = self.swirl.createSwirlFile(openedFile)
                    if swirlOpenedFile.path not in allFiles:
                        swirlFile.openedFiles.append(swirlOpenedFile)
        #hash and get package name
        for swf in self.swirl.swirlFiles:
            if os.path.exists(swf.path):
                swf.md5sum = sergeant.getHash(swf.path, swf.type)
                #TODO make this code nicer
                if any([ swf.path.startswith(a) for a in sergeant.specialFolders ]):
                    swf.package = None
                else:
                    swf.package = self._getPackage(swf.path)


    def getSwirl(self):
        """return the current swirl """
        return self.swirl 


    #TODO add a way to detach from executed programm
    def _straceCmd(self, execcmd, dynamicDependecies, files):
        """it execute the execmd with execve and then it trace process running and
        it adds all the dependency to the dynamicDependecies dictionary
        """
        try:
            from FingerPrint.syscalltracer import SyscallTracer
        except ImportError, e:
            raise IOError("Dynamic tracing is not supported on this platform: ", e)
        tracer = SyscallTracer()
        #TODO check for errors
        execcmd = shlex.split(execcmd)
        if not tracer.main(execcmd, dynamicDependecies, files):
            raise IOError("Unable to trace the process")



    #
    # package manager related suff
    # TODO move into their own class
    #
    def _detectedPackageManager(self):
        """ set the proper _getPackage*(self, path)
        function to handle rpm or dpkg based on /etc/issue content"""
        #rpm based OSes
        rpmOSs = ["red hat", "fedora", "suse", "centos", "scientific linux"]
        #dpkg based OSes
        dpkgOSs = ["debian",  "ubuntu"]

        f=open('/etc/issue')
        issues=f.read()
        f.close()
        if any(os in issues.lower() for os in rpmOSs):
            self._getPackage = self._getPackageRpm
        if any(os in issues.lower() for os in dpkgOSs):
            self._getPackage = self._getPackageDpkg
        if not '_getPackage' in dir(self):
            #we could not detect the pakcage manager
            self._getPackage = lambda  p : None


    def _getPackageDpkg(self, path):
        """given a path it return the package which provide that 
        path if if finds one only debian system"""
        cmd1 = ['dpkg', '-S']
        cmd2 = ['dpkg-query', '--show', "-f=${Package}\ ${Version}\ ${Architecture}", ]
        try:
            (package, returncode) = getOutputAsList(cmd1 + [path])
        except subprocess.CalledProcessError:
            #package not found
            return None
        except OSError:
            #cmd not found
            return None
        if returncode != 0 or len(package[0]) == 0:
            #the file is not tracked
            return None
        packageName = package[0].split(':')[0]
        try:
            (package, returncode) = getOutputAsList(cmd2 + [packageName])
            if returncode != 0:
                return None
            return package[0]
        except subprocess.CalledProcessError:
            #package not found
            return None
        except OSError:
            #cmd not found
            return None

    def _getPackageRpm(self, path):
        """given a path it return the package which provide that 
        path if if finds one
        only rpm based system"""
        cmd = ['rpm', '-qf']
        try:
            (package, returncode) = getOutputAsList(cmd + [path])
            if returncode != 0:
                return None
            return package[0]
        except subprocess.CalledProcessError:
            #package not found
            return None
        except OSError:
            #cmd not found
            return None
        


