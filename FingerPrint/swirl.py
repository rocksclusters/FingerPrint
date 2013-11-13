#!/bin/python
#
# LC
# 
# hold the in memory representation of a swirl
# list of binaries with their associated dependecy
# 

from datetime import datetime
import string, os, re


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
        self.ldconf_paths = []


    def isFileTracked(self, fileName):
        """return true if fileName is already tracked by this swirl """
        for f in self.swirlFiles:
            if fileName in f.getPaths():
                return True
        return False


    def createSwirlFile(self, fileName):
        """ given a fileName it return the associated swirlFile if present
        otherwise it creates a new one with all the symlinks resolved"""
        links = []
        while os.path.islink(fileName) :
            p = os.readlink(fileName)
            if not os.path.isabs(p):
                p = os.path.join( os.path.dirname(fileName), p)
            links.append(os.path.normpath(fileName))
            fileName = os.path.normpath(p)
        for swirlFile in self.swirlFiles:
            if swirlFile.path == fileName:
                #we found it
                swirlFile.setLinks(links)
                return swirlFile
        swirlFile = SwirlFile(fileName, links)
        self.swirlFiles.append(swirlFile)
        return swirlFile

    def getSwirlFileByProv(self, dependency):
        """find the swirl file which provides the given dependency"""
        for swF in self.swirlFiles:
            if dependency in swF.provides :
                return swF
        return None

    def get_all_rpaths(self):
        """    """
        # use a list to keep unique elements
        return_list = set()
        for swf in self.swirlFiles:
            return_list.update(swf.rpaths)
        return return_list


    def getLoader(self, swirlFile):
        """ return a swirlfile which is the loader of the given swirlFile

        it returns None in case the binaries is static"""
        for swf in self.getListSwirlFilesDependentStatic(swirlFile):
            if swf.isLoader():
                return swf
        return None


    def getListSwirlFilesDependentStaticAndDynamic(self, swirlFile):
        """given a swirlFile it returns a list of all its required swirlfiles
        It includes both static recursive and dynamic dependencies """
        returnList = self.getListSwirlFilesDependentStatic(swirlFile)
        for swF in swirlFile.dynamicDependencies:
            if swF not in returnList:
                returnList.append(swF)
        return returnList


    def getListSwirlFilesDependentStatic(self, swirlFile):
        """given a swirlFile it return a list of all the recursively required dependent
        swirlFiles (only static)

        it _recursively_ find all the required swirlFile invoking getListSwirlFile
        until all dependencies and dependencies of dependencies are resolved (when the
        loader start program 'a' which depend on lib 'b' which in its turn depends on
        lib 'c', the loader will load a, b, and c at the same time).  """

        returnList = []
        provides = set()

        # verifySubDepList list of deps we need to verify in this loop
        verifySubDepList = [swirlFile]
        # new verifySubDepList list of deps we need to verify in the next loop
        newVerifySubDepList = []
        while verifySubDepList :
            # I need another temporary list to accumulate the new dependency
            for swF in verifySubDepList:
                if not set(swF.staticDependencies).issubset( provides ):
                    # we found an unmet dependency
                    newDeps = self.getListSwirlFileProvide(swF.staticDependencies, returnList )
                    # add the new dependencies to the return list and to the list for the new loop
                    returnList += newDeps
                    newVerifySubDepList += newDeps
                    for newDep in newDeps:
                        provides |= set(newDep.provides)
            verifySubDepList = newVerifySubDepList
            newVerifySubDepList = []
        return returnList


    def getListSwirlFileProvide(self, dependencies, excludeSwirlFile=[]):
        """return a list of swirl file if found in the current swirl which can satisfy
        the given list of dependencies

        This function does not find recursive dependencies like
        getListSwirlFilesDependentStatic and getListSwirlFilesDependentStaticAndDynamic

        Parameters:
        ----------

        `dependency' a list of Dependency which should be satisfied
        `exludeSwirlFile' a list of swirlfile which should be excluded from the returned list """
        returnList = []
        for dep in dependencies:
            swirlFile = self.getSwirlFileByProv(dep)
            if swirlFile and swirlFile not in excludeSwirlFile and \
                swirlFile not in returnList:
                returnList.append(swirlFile)
        return returnList

    def getDependencies(self):
        """return a list with all the dependencies in this swirl"""
        depList = set()
        for i in self.execedFiles:
            depList |= set(i.staticDependencies)
        return depList

    def getDateString(self):
        """ return the creation time in a readable format"""
        return self.creationDate.strftime("%Y-%m-%d %H:%M")



    def printMinimal(self):
        """return a string representation of this swirl

        this method is called by the -d flags"""
        #header
        retStr = self.name + " " + self.getDateString() + "\n"
        #file list
        retStr += " -- File List -- \n"
        for swF in self.execedFiles:
            retStr += str(swF) + '\n'
            retStr += swF.printOpenedFiles(swF.path)
            for provider in self.getListSwirlFilesDependentStatic(swF):
                retStr += "  " + str(provider) + '\n'
                retStr += provider.printOpenedFiles(swF.path, "  ")
            for provider in swF.dynamicDependencies:
                retStr += "  " + str(provider) + ' --(Dyn)--\n'
                retStr += provider.printOpenedFiles(swF.path, "  ")
        return retStr

    def printVerbose(self, verbosity = 1):
        """return a verbose string representation of this swirl

        this method is called by the -d -v flags"""
        #header
        retStr = self.name + " " + self.getDateString() + "\n"
        #file list
        if self.cmdLine :
            retStr += " Command line: " + self.cmdLine + "\n"
        if self.ldconf_paths :
            retStr += " ls.so.conf path list:\n  " + '\n  '.join(self.ldconf_paths) + '\n'
        retStr += " -- File List -- \n"
        for swF in self.execedFiles:
            retStr += swF.printVerbose("", "", verbosity)
            retStr += swF.printOpenedFiles(swF.path)
            for provider in self.getListSwirlFilesDependentStatic(swF):
                retStr += provider.printVerbose("  ", "", verbosity)
                retStr += provider.printOpenedFiles(swF.path, "  ")
            for swFile in swF.dynamicDependencies:
                retStr += swFile.printVerbose("  ", "--(Dyn)--", verbosity)
                retStr += swFile.printOpenedFiles(swF.path, "  ")
        return retStr


    def __str__( self ):
        #header
        retStr = self.name + " " + self.getDateString() + "\n"
        #file list
        retStr += " -- File List -- "+str(len(self.swirlFiles))+"\n"
        for i in self.swirlFiles:
            retStr += str(i) + "\n"
        #dependency set
        return retStr


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

    def __eq__(self, other):
        # I need this to get the comparison working
        # so I can do if depA in depList:
        if other is None:
            return False
        return self.__dict__ == other.__dict__


class SwirlFile(Arch):
    """
    describe a file which is tracked by this swirl

    at the moment only ELF aka binary file are really supported

    1 swirlFile instance for each file in a given swirl for example if libabc is
    used by /bin/ls and /bin/ps they will both point to the same instance of libabc
    """
    def __init__(self, path, links):
        """create a swirl file starting from a file name"""
        Arch.__init__(self)
        self.path=path
        #symbolic links
        self.links=links
        # list of Dependency this file depend on
        self.staticDependencies=[]
        # list of Dependency that this file provides
        self.provides=[]
        # list of Swirl files
        self.dynamicDependencies=[]
        # opened files is a dictionary composed of binFile -> list of opened file
        # in this way we can track different opened file for each binFile with
        # shared libs
        self.openedFiles={}
        self.rpaths = []
        self.md5sum = None
        self.package = None
        # a reduced set of environment variables
        self.env = []
        # by default all files are data files (aka unknown type)
        self.type = "Data"

    def isLoader(self):
        """ return True if this swirl is a loader """
        for i in self.provides :
            if i.isLoader():
                return True
        return False

    def getPaths(self):
        """ return a list of path used by this SwirlFile"""
        return self.links + [self.path]

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
        if dependency in self.staticDependencies:
            return
        else:
            dependency.type = self.type
            self.staticDependencies.append(dependency)

    def addProvide(self, dependency):
        """if dependency is not already in the provides of this SwirlFile it gets
        added"""
        if dependency in self.provides:
            return
        else:
            dependency.type = self.type
            self.provides.append(dependency)

    def isExecutable(self):
        """ return true if this swirl is executable"""
        return 'ELF' in self.type and self.executable

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

         if provides==ture it returns the provides
        """
        retDict = {}
        if provides:
            transformList = self.provides
        else:
            transformList = self.staticDependencies
        for i in transformList:
            if i.major not in retDict.keys():
                retDict[i.major] = []
            if i not in retDict[i.major]:
                retDict[i.major].append(i)
        return retDict


    def __str__(self):
        """minimal string representation of this swrilfile aka its path"""
        return "  " + self.path


    def printVerbose(self, separator="", dynamic="", verbosity = 1):
        """a more detailed representation of this swrilfile """
        retString = separator + "  " + self.path + " " + dynamic
        if verbosity > 1:
            retString += " - " + self.md5sum
        if self.package:
            retString += " - " + self.package
        retString += "\n"
        for path in self.links:
            retString += separator + "  -> " + path + "\n"
        if self.env :
            retString += separator + "  Environment variables:\n"
            for e in self.env:
                retString += separator + "    " + e + "\n"
        if self.type not in "Data":
            retString += separator + "    Deps: " + string.join(self.getDependenciesDict().keys(), ', ') + "\n"
            retString += separator + "    Provs: " + string.join(self.getProvidesDict().keys(), ', ') + "\n"
        return retString


    def printOpenedFiles(self, execFile, tabs=""):
        """ return a string of opened file by the given executable path execFile"""
        retStr = ""
        if execFile in self.openedFiles:
            retStr += tabs + "    Opened files:\n"
            for swFile in self.openedFiles[execFile]:
                retStr += tabs + "    " + str(swFile) + '\n'
        return retStr

    def __hash__(self):
        """ so I can build sets of SwirlFile

        so far the SwirlFile.path are unique among a swirl so let's use them for the hash """
        return hash(tuple(self.path) + tuple(self.links))


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
        # the type of this dependency for the moment is the same as the type of the 
        # swirlfile it belongs to
        self.type = None

    @classmethod
    def fromString(cls, string):
        """ Create a dependency from a string returned by find-require find-provide
        """
        tempList = re.split('\(|\)',string)
        major = tempList[0]
        minor = ""
        if len(tempList) > 1 :
            #we have soname
            minor = tempList[1]
        newDep = cls(major, minor)
        if len(tempList) > 3:
            #set the 32/64 bits 
            #probably unecessary
            if "64bit" in tempList[3] :
                newDep.set64bits()
            elif "32bit" in tempList[3] :
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

    def isLoader(self):
        """ return true if this is the loader"""
        if self.major.startswith("ld-"):
            return True
        return False

    def getName(self):
        """return soname(minor_version)(arch) accordingly with the
        find-require find-provides syntax"""
        retString = self.major
        if self.minor or self.is64bits() :
            retString += "(" + self.minor + ")"
        if self.is64bits() :
            retString += "(64bit)"
        return retString

    def __hash__(self):
        return hash(str(self.arch) + str(self.major) + str(self.minor) + str(self.hwcap))

    def __str__(self):
        """ """
        return "" + self.major + "(" + self.minor + ")(" + self.arch + ")"

    def __repr__(self):
        return self.__str__()

