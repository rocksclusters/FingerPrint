#!/bin/python
#
# LC
# 
# hold the in memory representation of a swirl
# list of binaries with their associated dependecy
# 

from datetime import datetime
import StringIO

class Swirl:
    """main swirl class
    """
    def __init__(self, name, creationDate):
        self.name = name
        self.creationDate = creationDate
        self.fileList = []
        self.dependencySet = []

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


    def addDependencies(self, dependencySet):
        #TODO remove duplicate
        if type(dependencySet) is list:
            self.dependencySet += dependencySet
        else:
            self.dependencySet.append( dependencySet )

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
        string += str(self.dependencySet)
        return string


class SwirlFile(Swirl):
    """
    hold a file which is supported by this swirl
    """
    def __init__(self, path):
        self.path=path
        self.arch=None
        self.type=None
        self.dyn=True

    def isBinary(self):
        return self.type == 'ELF' and self.dyn


    def __str__(self):
        string = ""
        if self.type == "Data":
            string = "data "
        else:
            string = "bin  "
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



class XmlSerializer:
    """this serilizes the swirl into xml
    we can have multiple classes for serializing in other format
    TODO I don't really like this class structure yet...
    TODO this should be moved in another .py file
    """

    def __init__(self, fd):
        self.fd = fd

    def save(self, swirl ):
        self.fd.write("<xml>\n")
        self.fd.write("<name>" + swirl.name + "</name>\n")
        self.fd.write("<time>" + swirl.getDate() + "</time>\n")
        self.save_depset(swirl.dependencySet)
        self.fd.write("</xml>")

    def save_depset(self, dependencySet):
        self.fd.write("<depset>\n")
        for i in dependencySet.depSet:
            if isinstance(i, Dependency):
                self.fd.write("<dep>" + i.depname + "</dep>\n")
            else:
                self.save_depset(i)
        self.fd.write("</depset>\n")
    
    def read(self):
        """this should implement the read from xml
        """
        pass
            


