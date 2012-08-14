#!/usr/bin/python
#
# LC
#
# using existing static analysis tool to create a swirl into memory
#

from datetime import datetime
import subprocess
import os
#compatibility with python2.4
try:
    from hashlib import md5
except ImportError:
    from md5 import md5



from swirl import Swirl
from FingerPrint.plugins import PluginManager
from FingerPrint.utils import getOutputAsList


"""The getDependencies functions given a swirl file the have to figure out 
which are the dependencies of the file
"""

class Blotter:

    def __init__(self, name, fileList):
        """give a file list and a name construct a swirl into memory """
        self._pathCache = {}
        self._detectedPackageManager() 
        self.swirl = Swirl(name, datetime.now())
        for i in fileList:
            if os.path.isfile(i):
                swirlFile = PluginManager.getSwirl(i)
                self._hashDependencies(swirlFile)
                self.swirl.addFile(swirlFile)
            elif os.path.isdir(i):
                pass
            else:
                raise IOError("The file %s cannot be opened." % i)

       
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
                    fileToHash = newDep.pathList[-1]
                    fd=open(fileToHash)
                    md=md5()
                    md.update(fd.read())
                    fd.close()
                    newDep.hashList.append( md.hexdigest() )
                    #package Name
                    package = self._getPackage( fileToHash )
                    newDep.packageList.append( package )
                    #update the cache
                    self._pathCache[newDep.pathList[0]] = (newDep.pathList, newDep.hashList, newDep.packageList)

    def _detectedPackageManager(self):
        """ set the proper _getPackage(self, path)
        function to handle rpm or dpkg based on /etc/issue content"""
        #rpm based OSes
        rpmOSs = ["red hat", "fedora", "suse", "centos"]
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
        path if if finds one using dpkg"""
        cmd1 = ['dpkg', '-S']
        cmd2 = ['dpkg-query', '--show', "-f='${Package} ${Version} ${Architecture}'", ]
        try:
            package = getOutputAsList(cmd1 + [path])[0]
        except subprocess.CalledProcessError:
            #package not found
            return None
        except OSError:
            #cmd not found
            return None
        packageName = package.split(':')[0]
        try:
            package = getOutputAsList(cmd2 + [packageName])[0]
            return package
        except subprocess.CalledProcessError:
            #package not found
            return None
        except OSError:
            #cmd not found
            return None

    def _getPackageRpm(self, path):
        """TODO
        """
        cmd = ['rpm', '-qf']
        try:
            package = getOutputAsList(cmd + [path])[0]
            return package
        except subprocess.CalledProcessError:
            #package not found
            return None
        except OSError:
            #cmd not found
            return None
        


