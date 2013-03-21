#!/bin/python
#
# LC
# 
# hold the in memory representation of a swirl
# list of binaries with their associated dependecy
# 

from datetime import datetime
import StringIO, os, re


"""Swirl hold in memory the representation of a swirl.
A Swirl is a container of SwirlFiles aka files tracked by this swirl
"""

class Swirl(object):
    """main swirl class
    """
    def __init__(self, name, creationDate):
        self.name = name
        self.creationDate = creationDate
        # list of file tracked
        self.swirlFiles = []
        # files used to track this project
        self.execedFiles = []
        # command line used for dynamic tracing
        self.cmdLine = None

    def getDependencies(self):
        """the all the dependency of this swirl"""
        pass

    def getProvider(self, depname):
        """given a depname it find the swirlfile which provides it""" 
        pass


    def getSwirlFile(self, fileName):
        """ given a fileName it return the associated swirlFile if
        present, otherwise it creates a new one with all the symlinks resolved"""
        links = []
        while os.path.islink(fileName) :
            p = os.readlink(fileName)
            if not os.path.isabs(p):
                p = os.path.join( os.path.dirname(fileName), p)
            links.append(p)
            fileName = p
        for swirlFile in self.swirlFiles:
            if swirlFile.path == fileName:
                #we found it
                swirlFile.setLinks(links)
                return swirlFile
        swirlFile = SwirlFile(fileName, links)
        self.swirlFiles.append(swirlFile)
        return swirlFile


    def getDateString(self):
        """ return the creation time in a readable format"""
        return self.creationDate.strftime("%Y-%m-%d %H:%M")

    def __str__( self ):
        #header
        string = self.name + " " + self.getDateString() + "\n"
        #file list
        string += " -- File List -- "+str(len(self.swirlFiles))+"\n"
        for i in self.swirlFiles:
            string += str(i) + "\n"
        #dependency set
        return string


class Arch:
    """ old style classes for backward compability"""

    def __init__(self):
        self.arch = None

    #TODO use integer to save memory
    #this function are used by SwirlFile
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



class SwirlFile(Arch):
    """
    describe a file which is tracked by this swirl
    at the moment only ELF aka binary file are really supported
    """
    def __init__(self, path, links):
        """create a swirl file starting from a file name"""
        Arch.__init__(self)
        self.path=path
        #symbolic links
        self.links=links
        self.type=None
        # list of Dependency this file depend on
        self.staticDependencies=[]
        # list of Dependency that this file provides
        self.provides=[]
        # list of Swirl files
        self.dynamicDependency=[]
        self.openedFiles=[]
        self.md5sum = None
        self.package = None
        # by default all files are data files (aka unknown type)
        self.type = "Data"
        # i386 X86_64 noarch
        self.arch = None

    def setPluginName(self, name):
        """set the type of this file"""
        self.type = name

    def setLinks(self, links):
        """update the list of symbolic links pointing to this swirl file"""
        for link in links:
            if link not in self.links:
                self.links.append(link)

    def addDependency(self, dependency):
        """if dependency is not already in the static dependency of this swirl file it
        gets added"""
        for dep in self.staticDependencies:
            if dep == dependency:
                return
        self.staticDependencies.append(dependency)

    def addProvide(self, dependency):
        """if dependency is not already in the provides of this SwirlFile it gets
        added"""
        for prov in self.provides:
            if prov == dependency:
                return
        self.provides.append(dependency)



    def getListDependenciesFiles(self):
        """return a list of swirl file if found in the current swirl"""
        #TODO
        pass

    def isYourPath(self, path):
        """check if this path is part of this swirlFile looking into the links as well"""
        if path == self.path:
            return True
        else:
            for link in self.links:
                if link == path:
                    return True
        return False


    def getProvidesDict(self):
        return self.getDependenciesDict(True)

    def getDependenciesDict(self, provides=False):
        """ return a dictionary containing the dependencies with
        {'soname1' : ['version1', 'version2'],
         'soname2' : ['version1', 'version2']}

         if provides==ture it returns the provives
        """
        retDict = {}
        if provides:
            transformList = self.provides
        else:
            transformList = self.staticDependencies
        for i in transformList:
            if i.major not in retDict.keys():
                retDict[i.major] = []
            if i.minor not in retDict[i.major]:
                retDict[i.major].append(i.minor)
        return retDict

    def printDependencies(self):
        """ return a string with the static dependencies """


    def __str__(self):
        """ return a minimal string representation of this swrilfile"""
        retString = "  " + self.path + "\n"
        retString += "    Deps: " + str(self.getDependenciesDict()) + "\n"
        retString += "    Provs: " + str(self.getProvidesDict()) + "\n"
        return retString



class Dependency(Arch):
    """this class reperesent a dependency declarations, it can be used to
    represent either a dependency or a provices in a swirlFile. It is an
    abstract representation of a piece of software"""

    def __init__(self, major, minor = None, hwcap=None):
        Arch.__init__(self)
        # string representing the main dependency
        # for elf is the soname of the binary path
        self.major = major
        # a list of version supported by this dependency
        # for elf this is the simobl versions
        # http://tldp.org/HOWTO/Program-Library-HOWTO/miscellaneous.html#VERSION-SCRIPTS
        self.minor = minor
        # hwcap (shouldn't this be part of swirlfile)
        self.hwcap = hwcap

    @classmethod
    def fromString(cls, string):
        """ Create a dependency from a string returned by find-require find-provide
        """
        tempList = re.split('\(|\)',string)
        major = tempList[0]
        minor = None
        if len(tempList) > 1 :
            #we have soname
            minor = string.split('(')[1].split(')')[0]
        newDep = cls(major, minor)
        if len(tempList) > 3:
            #set the 32/64 bits 
            #probably unecessary
            if tempList[3].find("64bit") >= 0 :
                newDep.set64bits()
            elif tempList[3].find("32bit") >= 0 :
                #this should never happen
                newDep.set32bits()
        else:
            #no parenthesis aka 32 bit 
            newDep.set32bits()
        return newDep

    def getMajor(self):
        return self.major

    def getMinor(self):
        return self.minor

    def getName(self):
        """return canonical representation of this dependency """
        return self.__str__()


    def __str__(self):
        """ """
        return "" + self.major + "(" + self.minor + ")"


class Provide:
    """remove me """
    pass
