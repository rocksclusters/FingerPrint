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
The two main components are SwirlFile aka files tracked by this swirl
Dependency aka dependencies needed by SwirlFile to run
"""

class Swirl(object):
    """main swirl class
    """
    def __init__(self, name, creationDate):
        self.name = name
        self.creationDate = creationDate
        #list of file tracked
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
        return sorted(tempDep, key=str)


    def getDependency(self, depname):
        """given a depname it find the dep amond all the swirlFile.dependencies lists
        and return its object"""
        for dep in self.getDependencies():
            if dep.depname == depname:
                return dep
        return None


    def getProvides(self):
        """get the full list of Provide in this swirl
        deleting duplicate"""
        tempPro=[]
        for file in self.swirlFiles:
            for prov in file.provides:
                if prov not in tempPro:
                    tempPro.append(prov)
        return sorted(tempPro, key=str)


    def addFile(self, swirlFile):
        """add a file to the list of the tracked files"""
        self.swirlFiles.append(swirlFile)

    def getSwirlFile(self, fileName):
        """ given a fileName it return the associated swirlFile if
        present, otherwise None"""
        for swirlFile in self.swirlFiles:
            if swirlFile.path == fileName:
                return swirlFile
        return None

    def getDateString(self):
        """ return the creation time in a readable format"""
        return self.creationDate.strftime("%Y-%m-%d %H:%M")

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
        #do we need this?
        self.md5sum = None
        self.files = []

    def setPluginName(self, name):
        """this hold the name of the plugin who handled this
        attribute used by SwirlFile Dependency and Provide"""
        self.pluginName = name
    
    def getPluginName(self):
        return self.pluginName

    def getListDependenciesFiles(self):
        """return a list of all the files this swirlfile depends on"""
        returnList = []
        for i in self.dependencies:
            returnList += i.pathList
        return returnList

    def addDependency(self, dep):
        """ dep must be a Dependency object"""
        self.dependencies.append(dep)

    def getDependency(self, depname):
        """ given a dependency name it returns its object if found in the
        dependecies list"""
        for dep in self.dependencies:
            if dep.depname == depname:
                return dep
        return None

    def getOrderedDependencies(self):
        """ return a dictionary containing the dependencies with
        {'soname1' : ['version1', 'version2'],
         'soname2' : ['version1', 'version2']}
        """
        retDict = {}
        for i in self.dependencies:
            if i.getBaseName() not in retDict.keys():
                retDict[i.getBaseName()] = []
            if i.getVersion() not in retDict[i.getBaseName()]:
                retDict[i.getBaseName()].append(i.getVersion())
        return retDict

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
            string += "  Deps: "
            string += Dependency.printListDependencies(self.dependencies)
        if len(self.provides) > 0:
            string += "  Prov: "
            string += Dependency.printListDependencies(self.provides)
        if self.files:
            string += "  Files: \n"
            for i in self.files:
                string += "    " + i + "\n"
        return string


class Dependency(SwirlFile):
    """ This class represent a single dependency
    """

    def __init__(self, name):
        self.depname = name
        self.hashList = []
        self.arch = None
        self.pluginName = None
        self.pathList = []
        self.packageList = []
        #http://www.trevorpounds.com/blog/?p=33
        #http://www.akkadia.org/drepper/symbol-versioning
        #self.symbolVersion = None

    def getBaseName(self):
        """ depname are generally in the form of 'python2.7(sys)' or 
        'libc.so.6(LIBC_2_4)' this function return only the first part of the 
        dependency name also called soname"""
        return self.depname.split('(')[0]

    def getVersion(self):
        """return the version of this dependency aka string inside the first parenthesis"""
        return self.depname.split('(')[1].split(')')[0]

    def printPaths(self):
        """ return a string which represent the paths of this dependency"""
        string = ""
        for path, hash, package in zip(self.pathList, self.hashList, self.packageList):
            string += "\n        " + path
            if hash:
                string += " - " + hash
            if package:
                string += " (" + package + ")"
        return string


    def __str__( self ):
        string = self.depname
        if hasattr(self, 'pathList'):
            string += self.printPaths()
        return string

    def __repr__(self):
        #to print list properly i need this method
        return "\n    " + self.__str__() 

    @staticmethod
    def printListDependencies(depList):
        """given a list of depenendency it return a string with a human readable
        representation of the list """
        string = ""
        depBaseName = []
        for i in depList:
            name = i.getBaseName()
            if name not in depBaseName:
                depBaseName.append(name)
        for depBaseName in depBaseName:
            string += "\n    " + depBaseName + " "
            for dep in depList:
                if depBaseName in dep.depname:
                    string += "(" + dep.getVersion() + ") "
                    path = dep.printPaths()
            string += path
        string += "\n"
        return string


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


