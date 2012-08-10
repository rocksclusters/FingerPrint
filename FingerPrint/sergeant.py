#!/usr/bin/python
#
# LC
#
# given a swirl it detect if it can run on the system
#

import os

from swirl import Swirl
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





class Sergeant:

    def __init__(self, swirl, extraPath=None):
        """ swirl is a valid Swirl object
        extraPath is a list of string containing system path which should 
        be included in the search of dependencies"""
        self.swirl = swirl
        self.extraPath = extraPath
        self.error = []

    def setExtraPath(self, path):
        """
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
        """check all the dep for md5sum changes
        """
        self.error = []
        depList = self.swirl.getDependencies()
        returnValue = True
        for dep in depList:
            for file, hash in zip(dep.pathList, dep.hashList):
                #pass
                if hash :
                    fd=open(file)
                    md=md5()
                    md.update(fd.read())
                    fd.close()
                    if hash != md.hexdigest():
                        self.error.append(file)
                        returnValue = False
        return returnValue


    def getError(self):
        """return a string descripting what failed the check"""
        return sorted(self.error)

       
    def getSwirl(self):
        """return the current swirl """
        return self.swirl 


