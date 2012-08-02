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

class Swirl(object):
    """main swirl class
    """
    def __init__(self, name, creationDate):
        self.name = name
        self.creationDate = creationDate
        self.swirlFiles = []

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


    def getDependencies(self):
        """the all the dependency of this swirl"""
        tempDep=[]
        for file in self.swirlFiles:
            for dep in file.dependencies:
                if dep not in tempDep:
                    tempDep.append(dep)
        #tempDep now contains all the dependency
        #I need to take the provides available in this swirl off of it
        provides = map( lambda x: x.provname, self.getProvides())
        #this removes from tempDep provides element :-o
        tempDep[:] = [i for i in tempDep if not i.depname in provides]
        return tempDep


    def getProvides(self):
        """get the full list of Provide in this swirl
        deleting duplicate"""
        tempPro=[]
        for file in self.swirlFiles:
            for prov in file.provides:
                if prov not in tempPro:
                    tempPro.append(prov)
        return tempPro


    def save(self, saver):
        """this method is used to serialize this class hierarcy
        TODO not used yet
        """
        saver.save(self)


    def addFile(self, swirlFile):
        """add a file to the list of the tracked files"""
        self.swirlFiles.append(swirlFile)

       
    def getBinaryFiles(self): 
        """Return a list of file which should be checked for dependency or provides"""
        retList=[]
        for i in self.swirlFiles:
            if i.isBinary():
                retList.append(i)
        return retList


    def getDateString(self):
        return self.creationDate.strftime("%A, %d. %B %Y %I:%M%p")

    def __eq__(self, other):
        #I need this to get the 
        #depA in depList working
        #see function getProvides and getDependecies
        if other is None:
            return False
        return self.__dict__ == other.__dict__

    def __str__( self ):
        #header
        string = self.name + " " + self.getDateString() + "\n"
        #file list
        string += " -- File List -- \n"
        for i in self.swirlFiles:
            string += str(i) + "\n"
        #dependency set
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
        self.dependencies=[]
        self.provides=[]
        self.pluginName=None

    def setPluginName(self, name):
        """this hold the name of the plugin who handled this
        attribute used by SwirlFile Dependency and Provide"""
        self.pluginName = name
    
    def getPluginName(self):
        return self.pluginName

    def isBinary(self):
        return self.type.startswith( 'ELF' ) 

    def setShared(self):
        """ """
        self.type = 'ELF_sha'    

    def setExecutable(self):
        """ """
        self.type = 'ELF_exe'

    def addDependency(self, dep):
        """ dep must be a Dependency object"""
        self.dependencies.append(dep)

    def addProvide(self, provide):
        """ provide is a Provide object"""
        self.provides.append(provide)

    def __str__(self):
        string = "File type: "
        if self.type == "Data":
            string += "data     "
        else:
            string += str(self.type) + "  "
        string += " File name: " + self.path + "\n"
        if len(self.dependencies) > 0:
            string += "  Deps: " + str(self.dependencies) + "\n"
        if len(self.provides) > 0:
            string += "  Prov: " + str(self.provides) + "\n"
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


class Dependency(SwirlFile):
    """ This class represent a single dependency
    """

    def __init__(self, name):
        self.depname = name
        self.filehash = None
        self.arch = None
        self.pluginName = None
        #http://www.trevorpounds.com/blog/?p=33
        #http://www.akkadia.org/drepper/symbol-versioning
        self.symbolVersion = None

    def __str__( self ):
        string = self.depname
        return string

    def __repr__(self):
        #to print list properly i need this method
        return "\n    " + self.__str__() 



class Provide(SwirlFile):
    """ This class represent a single dependency
    """

    def __init__(self, name):
        self.provname = name

    def __str__( self ):
        string = self.provname
        return string

    def __repr__(self):
        #to print list properly i need this method
        return "\n    " + self.__str__()


