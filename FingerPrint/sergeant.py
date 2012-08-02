#!/usr/bin/python
#
# LC
#
# given a swirl it detect if it can run on the system
#

import os
import ctypes

from swirl import Swirl
from FingerPrint.plugins import PluginManager
from FingerPrint.serializer import PickleSerializer




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
        #TODO implement extrapath
        self.extraPath = extraPath
        self.error = []


    def check(self):
        """actually perform the check on the system and return True if all 
        the dependencies can be satisfied on the current system
        """
        depList = self.swirl.getDependencies()
        returnValue = True
        for dep in depList:
            if not PluginManager.isDepsatisfied(dep):
                self.error.append(dep.depname)
                returnValue = False
        return returnValue

    def getError(self):
        """TODO return a string descripting what failed the check"""
        return self.error


    def isDepsatified(self, dependency):
        """verify that the dependency passed can be satified on this system
        and return True if so
        TODO make this a little more extensible
        """
        soname = dependency.depname.split('(')[0]
        try:
            #TODO this verify only the soname we need to check for version too!
            ctypes.cdll.LoadLibrary(soname) 
            return True
        except OSError:
            return False
       
    def getSwirl(self):
        """return the current swirl """
        return self.swirl 


