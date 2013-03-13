#!/usr/bin/python
#
# LC
#
# using existing static analysis tool to create a swirl into memory
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
            if libPath not in dynamicDependecies[binaryFile]:
                dynamicDependecies[binaryFile].append( libPath )


class Blotter:

    def __init__(self, name, fileList, processIDs, execCmd):
        """give a file list and a name construct a swirl into memory """
        self._pathCache = {}
        self._detectedPackageManager() 
        self.swirl = Swirl(name, datetime.now())
        # 
        # dependencies discovered with dinamic methods
        # dynamicDependencies = { 'binarypath' : [list of file it depends to],
        # '/bin/bash' : ['/lib/x86_64-linux-gnu/libnss_files-2.15.so',
        # '/lib/x86_64-linux-gnu/libnss_nis-2.15.so']}
        dynamicDependecies = {}

        if execCmd :
            self._straceCmd(execCmd, dynamicDependecies)

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
            if os.path.islink(i):
                swirlFile = SwirlFile( i )
                swirlFile.type = 'link'
                self.swirl.addFile(swirlFile)
            elif os.path.isfile(i):
                if i in dynamicDependecies:
                    swirlFile = PluginManager.getSwirl(i)
                else:
                    swirlFile = PluginManager.getSwirl(i)
                #self._hashDependencies(swirlFile)
                self.swirl.addFile(swirlFile)
            elif os.path.isdir(i):
                pass
            else:
                raise IOError("The file %s cannot be opened." % i)
        # I need two hash the dependency twice because I need to resolve all the 
        # symbolic lynk which is done in the _hashDependency before I add the dinamyc 
        # dependencies
        for i in self.swirl.swirlFiles:
            self._hashDependencies(i)
        #
        # we might need to add the dynamic dependencies to the swirl
        # if they did not get detected already
        reHash = False
        for fileName in dynamicDependecies.keys():
            swirlFile = self.swirl.getSwirlFile(fileName)
            listDepFile = swirlFile.getListDependenciesFiles()
            for dynamicDepFile in dynamicDependecies[fileName]:
                if dynamicDepFile not in listDepFile:
                    newDeps = PluginManager.getDependeciesFromPath(dynamicDepFile)
                    for i in newDeps:
                        # let's check if the swirlFile already has this dependency
                        oldDep = swirlFile.getDependency( i.depname )
                        if oldDep and len(oldDep.pathList) < 1 :
                            # this is an unresolved dependency let's use the new one
                            swirlFile.dependencies.remove(oldDep)
                            swirlFile.addDependency( i )
                        else:
                            swirlFile.addDependency( i )
                        reHash = True
        # I need to rehash the new dependency
        if reHash :
            for i in self.swirl.swirlFiles:
                self._hashDependencies(i)


    def getSwirl(self):
        """return the current swirl """
        return self.swirl 


    def _hashDependencies(self, swirlFile):
        """after the swirlFile is created it add md5sum for each dependency """
        for newDep in swirlFile.dependencies:
            if len(newDep.pathList) > 0:
                # let's check in the cache
                if newDep.pathList[0] in self._pathCache :
                    newDep.pathList, newDep.hashList, newDep.packageList = self._pathCache[newDep.pathList[0]]
                else:
                    #new file we have to do it
                    p = newDep.pathList[0]
                    #add all the simbolik links till we hit the real file
                    while os.path.islink(newDep.pathList[-1]) :
                        p = os.readlink(newDep.pathList[-1])
                        if not os.path.isabs(p):
                            p = os.path.join(
                                    os.path.dirname(newDep.pathList[-1]), p)
                        newDep.packageList.append( None )
                        newDep.hashList.append( None )
                        newDep.pathList.append( p )
                    #md5
                    fileToHash = p
                    newDep.hashList.append(sergeant.getHash(fileToHash, newDep.pluginName))
                    #package Name
                    package = self._getPackage( fileToHash )
                    newDep.packageList.append( package )
                    #update the cache
                    self._pathCache[newDep.pathList[0]] = (newDep.pathList, newDep.hashList, newDep.packageList)


    # TODO add a way to detach from executed programm
    def _straceCmd(self, execcmd, dynamicDependecies):
        """it execute the execmd with execve and then it trace process running and
        it adds all the dependency to the dynamicDependecies dictionary
        """
        try:
            from FingerPrint.syscalltracer import SyscallTracer
        except ImportError, e:
            raise IOError("Dynamic tracing is not supported on this platform")
        tracer = SyscallTracer()
        #TODO check for errors
        execcmd = shlex.split(execcmd)
        if not tracer.main(execcmd, dynamicDependecies):
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
        cmd2 = ['dpkg-query', '--show', "-f='${Package} ${Version} ${Architecture}'", ]
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
        


