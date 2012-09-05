#!/usr/bin/python
#
# LC
#
# given a swirl it detect if it can run on the system
#

import os

from swirl import Swirl
import utils
from FingerPrint.plugins import PluginManager
from FingerPrint.serializer import PickleSerializer
#compatibility with python2.4
try:
    from hashlib import md5
except ImportError:
    from md5 import md5




"""Given a swirl it detect if it can run on this system
"""


def readFromPickle(fileName):
    """helper function to get a swirl from a filename"""
    inputfd = open(fileName)
    pickle = PickleSerializer( inputfd )
    swirl = pickle.load()
    inputfd.close()
    return Sergeant(swirl)



#this variable is use by getHash
_isPrelink = None

def getHash(fileName, pluginName):
    """Given a valid fileName it returns a string containing a md5sum
    of the file content. If we are running on a system which prelink
    binaries (aka RedHat based) the command prelink must be on the PATH"""
    global _isPrelink
    if _isPrelink == None:
        #first execution let's check for prelink
        _isPrelink = utils.which("prelink")
        if _isPrelink == None:
            _isPrelink = ""
        else:
            print "Using: ", _isPrelink
    if pluginName == 'ELF' and len(_isPrelink) > 0:
        #let's use prelink for the md5sum
        temp = utils.getOutputAsList([_isPrelink, '-y', '--md5', fileName])
        return temp[0]
    try:
        #ok let's do standard md5sum
        fd=open(fileName)
        md=md5()
        md.update(fd.read())
        fd.close()
        return md.hexdigest()
    except IOError:
        #file not found
        return None


class Sergeant:

    def __init__(self, swirl, extraPath=None):
        """ swirl is a valid Swirl object
        extraPath is a list of string containing system path which should 
        be included in the search of dependencies"""
        self.swirl = swirl
        self.extraPath = extraPath
        self.error = []

    def setExtraPath(self, path):
        """path is a string containing a list of path separtated by :
        This pathes will be added to the search list when looking for dependency
        """
        self.extraPath = path.split(':')


    def check(self):
        """actually perform the check on the system and return True if all 
        the dependencies can be satisfied on the current system
        """
        self.error = []
        depList = self.swirl.getDependencies()
        returnValue = True
        PluginManager.addSystemPaths(self.extraPath)
        for dep in depList:
            if not PluginManager.isDepsatisfied(dep):
                self.error.append(dep.depname)
                returnValue = False
        return returnValue

    def checkHash(self):
        """check if any dep was modified since the swirl file creation 
        (using checksuming) """
        self.error = []
        depList = self.swirl.getDependencies()
        returnValue = True
        for dep in depList:
            for file, hash in zip(dep.pathList, dep.hashList):
                if hash and hash != getHash(file, dep.pluginName):
                    #wrong hash values
                    print dep.depname, " orig ", hash, " computed ", getHash(file, dep.pluginName)
                    self.error.append(dep.depname)
                    returnValue = False
        return returnValue


    def getError(self):
        """after running check or checkHash if they returned False this 
        function return a list with the dependencies name that failed
        """
        return sorted(self.error)

       
    def getSwirl(self):
        """return the current swirl """
        return self.swirl 


