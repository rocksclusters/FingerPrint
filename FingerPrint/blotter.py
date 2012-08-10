#!/usr/bin/python
#
# LC
#
# using existing static analysis tool to create a swirl into memory
#

from datetime import datetime
import os
#compatibility with python2.4
try:
    from hashlib import md5
except ImportError:
    from md5 import md5



from swirl import Swirl
from FingerPrint.plugins import PluginManager


"""The getDependencies functions given a swirl file the have to figure out 
which are the dependencies of the file
"""

class Blotter:

    def __init__(self, name, fileList):
        """give a file list and a name construct a swirl into memory """
        self._pathCache = {}
        self._md5Cache = {}
        self.swirl = Swirl(name, datetime.now())
        for i in fileList:
            if os.path.isfile(i):
                swirlFile = PluginManager.getSwirl(i)
                self.hashDependencies(swirlFile)
                self.swirl.addFile(swirlFile)
            elif os.path.isdir(i):
                pass
            else:
                raise IOError("The file %s cannot be opened." % i)

       
    def getSwirl(self):
        """return the current swirl """
        return self.swirl 



    def hashDependencies(self, swirlFile):
        """after the swirl is created it add md5sum dependency
        """
        for newDep in swirlFile.dependencies:
            # let's check in the cache
            if newDep.depname in self._pathCache :
                newDep.pathList += self._pathCache[newDep.depname]
                newDep.hashList += self._md5Cache[newDep.depname]
            else:
                #new file we have to do it
                if len(newDep.pathList) > 0:
                    p = newDep.pathList[0]
                    #add all the simbolik links till we hit the real file
                    while os.path.islink(newDep.pathList[-1]) :
                        p = os.readlink(newDep.pathList[-1])
                        if not os.path.isabs(p):
                            p = os.path.join(os.path.dirname(newDep.pathList[-1]), p)
                        newDep.hashList.append( None )
                        newDep.pathList.append( p )
                    #md5
                    fileToHash = newDep.pathList[-1]
                    fd=open(fileToHash)
                    md=md5()
                    md.update(fd.read())
                    fd.close()
                    newDep.hashList.append( md.hexdigest() )
                    #update the cache
                    self._md5Cache[newDep.depname] = newDep.hashList
                    self._pathCache[newDep.depname] = newDep.pathList



