#!/bin/python
#
# LC
# 
# hold the in memory representation of a swirl
# list of binaries with their associated dependecy
# 

from datetime import datetime
import StringIO


"""Swirl hold in memory the representation of a swirl.
The two main components are SwirlFile aka file tracked by this swirl
and Dependency aka dependency which one of the swirl file needs to run
"""

class Swirl:
    """main swirl class
    """
    def __init__(self, name, creationDate):
        self.name = name
        self.creationDate = creationDate
        self.fileList = []
        self.dependency = []

    #TODO use integer to save memory
    #this function are used by SwirlFile and Dependency subclasses
    def set64bits(self):
        self.arch="x86_64"

    def set32bits(self):
        self.arch="i386"

    def is32bits(self):
        if self.arch == "i386":
            return True
        else:
            return False

    def is64bits(self):
        if self.arch == "x86_64":
            return True
        else:
            return False


    def addDependencies(self, dependency):
        #TODO should dependency be part of swirl file?
        if type(dependency) is list:
            self.dependency += dependency
        else:
            self.dependency.append( dependency )

    def save(self, saver):
        """this method is used to serialize this class hierarcy
        TODO not used yet
        """
        saver.save(self)

    def addFile(self, swirlFile):
        """add a file to the list of the tracked files"""
        self.fileList.append(swirlFile)

       
    def getBinaryFiles(self): 
        """Return a list of binary file with dinamic libraries"""
        retList=[]
        for i in self.fileList:
            if i.isBinary():
                retList.append(i)
        return retList


    def getDateString(self):
        return self.creationDate.strftime("%A, %d. %B %Y %I:%M%p")        


    def __str__( self ):
        #header
        string = self.name + " " + self.getDateString() + "\n"
        #file list
        string += " -- File List -- \n"
        for i in self.fileList:
            string += str(i) + "\n"
        #dependency set
        string += " -- Dependency Set -- \n"
        string += str(self.dependency)
        return string


class SwirlFile(Swirl):
    """
    describe a file which tracked by this swirl
    at the moment only ELF aka binary file are supported
    """
    def __init__(self, path):
        self.path=path
        self.arch=None
        self.type=None
        #do we need this?
        self.dyn=True

    def isBinary(self):
        return self.type.startswith( 'ELF' ) 

    def setShared(self):
        """ """
        self.type = 'ELF_sha'    

    def setExecutable(self):
        """ """
        self.type = 'ELF_exe'


    def __str__(self):
        string = ""
        if self.type == "Data":
            string = "data     "
        else:
            string = self.type + "  "
        if self.arch == "x86_64":
            string += "x86_64 "
        elif self.arch == "i386":
            string += "i386   "
        else:
            string += "       "
        string += self.path
        return string

        
class DependencySet(Swirl):
    """does it make sense to have recursive dependency set?
    or should they just be a flat list?
    TODO not used at the moment
    """ 

    def __init__(self):
        self.depSet = []

    def addDependency(self, dependency):
        self.depSet.append(Dependency(dependency))
    
    def __str__( self ):
        string=""
        for i in self.depSet:
            string += str(i) + "\n"  
        return string


class Dependency(Swirl):
    """ This class represent a single dependency
    """

    def __init__(self, name):
        self.depname = name
        self.filehash = None
        self.arch = None
        #http://www.trevorpounds.com/blog/?p=33
        #http://www.akkadia.org/drepper/symbol-versioning
        self.symbolVersion = None

    def __str__( self ):
        string = self.arch + "  " + self.depname
        if self.symbolVersion:
            string += " " + self.symbolVersion
        return string

    def __repr__(self):
        #to print list properly i need this (python oddities)
        return "\n" + self.__str__()


