#!/bin/python
#
# LC
# 
# hold the in memory representation of a swirl
# list of binaries with their associated dependecy
# 

from datetime import datetime
import string, os, re


class Swirl(object):
    """
    Swirl hold in memory the representation of a swirl. It is made of a list
    of SwirlFiles aka files tracked by this swirl. There is one instance of
    this class for each fingerprint process.

    :type name: string
    :param name: a internal simbolic name for this swirl

    :type creationDate: :class:`datetime.datetime`
    :param creationDate: the creation time of this Swirl
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
        """
        return true if fileName is already tracked by this swirl

        :type fileName: string
        :param fileName: the path of the file to look up

        :rtype: bool
        :return: true if fileName is tracked by this swirl
        """
        for f in self.swirlFiles:
            if fileName in f.getPaths():
                return True
        return False


    def createSwirlFile(self, fileName):
        """
        given a fileName it return the associated swirlFile if present
        otherwise it creates a new one with all the symlinks resolved

        :type fileName: string
        :param fileName: the path of the file to add to this swirl

        :rtype: :class:`FingerPrint.swirl.SwirlFile`
        :return: a SwirlFile for the given fileName
        """
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
        """
        find the swirl file which provides the given dependency

        :type dependency: :class:`FingerPrint.swirl.Dependency`
        :param dependency: the dependency which should be satisfied

        :rtype: :class:`FingerPrint.swirl.SwirlFile`
        :return: a SwirlFile which provides the given dependency None if it
                 could not be found
        """
        for swF in self.swirlFiles:
            if dependency in swF.provides :
                return swF
        return None

    def _get_all_rpaths(self):
        """ TODO unused """
        # use a list to keep unique elements
        return_list = set()
        for swf in self.swirlFiles:
            return_list.update(swf.rpaths)
        return return_list


    def getLoader(self, swirlFile):
        """
        return a swirlfile which is the loader of the given swirlFile

        :type swirlFile: :class:`FingerPrint.swirl.SwirlFile`
        :param swirlFile: a swirlFile which is part of this Swirl

        :rtype: :class:`FingerPrint.swirl.SwirlFile`
        :return: a SwirlFile which is the loader of the input swirlFile
                 or None in case the input swirlFile is static
        """
	# iterate through the dependencies till we find the loader
        for swf in self.getListSwirlFilesDependentStatic(swirlFile):
            if swf.isLoader():
                return swf
        return None


    def getListSwirlFilesDependentStaticAndDynamic(self, swirlFile):
        """
        Given a swirlFile it returns a list of all its required swirlfiles.
        It includes both static recursive and dynamic dependencies

        :type swirlFile: :class:`FingerPrint.swirl.SwirlFile`
        :param swirlFile: a swirlFile which is part of this Swirl

        :rtype: list
        :return: a list of :class:`FingerPrint.swirl.SwirlFile` which 
                 are all the dependencies of the input swirlFile
        """
        returnList = self.getListSwirlFilesDependentStatic(swirlFile)
        for swF in swirlFile.dynamicDependencies:
            if swF not in returnList:
                returnList.append(swF)
        return returnList


    def getListSwirlFilesDependentStatic(self, swirlFile):
        """
        Given a swirlFile it return a list of all the recursively required dependent
        swirlFiles (only static).

        It _recursively_ find all the required swirlFile invoking getListSwirlFile
        until all dependencies and dependencies of dependencies are resolved (when the
        loader start program 'a' which depend on lib 'b' which in its turn depends on
        lib 'c', the loader will load a, b, and c at the same time).  


        :type swirlFile: :class:`FingerPrint.swirl.SwirlFile`
        :param swirlFile: a swirlFile which is part of this Swirl

        :rtype: list
        :return: a list of :class:`FingerPrint.swirl.SwirlFile` which 
                 are all the static dependencies of the input swirlFile
        """
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
        """
        return a list of :class:`FingerPrint.swirl.SwirlFile` from the current Swirl
        which can satisfy the given list of dependencies

        This function does not find recursive dependencies like
        getListSwirlFilesDependentStatic and getListSwirlFilesDependentStaticAndDynamic

        :type dependencies: list
        :param dependencies: a list of :class:`FingerPrint.swirl.Dependency`
        :type exludeSwirlFile: list
        :param exludeSwirlFile: a list of :class:`FingerPrint.swirl.SwirlFile` which
                                should be excluded from the returned list

        :rtype: list
        :return: a list of :class:`FingerPrint.swirl.SwirlFile` which can satisfy 
                 the list of dependencies
        """
        returnList = []
        for dep in dependencies:
            swirlFile = self.getSwirlFileByProv(dep)
            if swirlFile and swirlFile not in excludeSwirlFile and \
                swirlFile not in returnList:
                returnList.append(swirlFile)
        return returnList

    def getDependencies(self):
        """return a list with all the dependencies in this swirl

        :rtype: list
        :return: a list of :class:`FingerPrint.swirl.Dependency` which are needed
                 inside by all the binaries inside this Swirl
        """
        depList = set()
        for i in self.execedFiles:
            depList |= set(i.staticDependencies)
        return depList

    def getDateString(self):
        """
        return the creation time in a readable format

        :rtype: string
        :return: a string with the representation of the creation
                 time of this swirl
        """
        return self.creationDate.strftime("%Y-%m-%d %H:%M")

    def printVerbose(self, verbosity = 1):
        """
        return a string representation of this swirl. This method is called by 
        the -d flags

        :type verbosity: int
        :param verbosity: the level of verbosity 0 minimum 2 maximum


        :rtype: string
        :return: a string with a representation of this Swirl
        """
        #header
        retStr = self.name + " " + self.getDateString() + "\n"
        if verbosity > 0:
            if self.cmdLine :
                retStr += " Command line: " + self.cmdLine + "\n"
            if self.ldconf_paths :
                retStr += " ls.so.conf path list:\n  " + '\n  '.join(self.ldconf_paths) + '\n'
        #file list
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

    #this function are used by SwirlFile and Dependency
    def set64bits(self):
        """set 64 bit architecture"""
        self.arch="x86_64"

    def set32bits(self):
        """set 32 bit architecture"""
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
    Encapsulate all the info we need to track for each file.  
    At the moment only ELF aka binary file are really supported everything else
    is considered 'data'.

    There is only 1 swirlFile instance for each file in a given swirl for example
    if libabc is used by /bin/ls and /bin/ps they will both point to the same
    instance of libabc

    :type path: string
    :param path: The aboslute path of this SwirlFile this is the identificative
                 key for this SwirlFile

    :type links: list
    :param links: a list of string with all the discovered simbolic links pointing
                  to this SwirlFile

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
        self.executable = False

    def isLoader(self):
        """
        :rtype: bool
        :return: return True if this SwirlFile is a loader
        """
        for i in self.provides :
            if i.isLoader():
                return True
        return False

    def getPaths(self):
        """
        return a list of path used by this SwirlFile (it includes all the
        symbolic links)

        :rtype: list
        :return: return a list of strings
        """
        return self.links + [self.path]

    def setPluginName(self, name):
        """
        Set the plugin type of this file (at the moment we have only elf plugin)

        :type name: string
        :param name: the plugin name as in FingerPrint/plugins
        """
        self.type = name

    def setLinks(self, links):
        """
        update the list of symbolic links pointing to this swirl file

        :type links: list
        :param links: a list of string with file path names
        """
        for link in links:
            if link not in self.links:
                self.links.append(link)

    def addDependency(self, dependency):
        """if dependency is not already in the static dependency of this swirl file it
        gets added

        :type dependency: :class:`FingerPrint.swirl.Dependency`
        :param dependency: an instance of Dependency to be added
        """
        if dependency in self.staticDependencies:
            return
        else:
            dependency.type = self.type
            self.staticDependencies.append(dependency)

    def addProvide(self, dependency):
        """
        if dependency is not already in the provides of this SwirlFile it gets added

        :type dependency: :class:`FingerPrint.swirl.Dependency`
        :param dependency: an instance of Dependency to be added
        """
        if dependency in self.provides:
            return
        else:
            dependency.type = self.type
            self.provides.append(dependency)

    def isELFExecutable(self):
        """
        :rtype: bool
        :return: true if this SwirlFile is executable
        """
        # TODO not used, it can be removed
        return 'ELF' in self.type and self.executable

    def isYourPath(self, path):
        """
        check if this path is part of this swirlFile looking into the links as well

        :type path: string
        :param path: a file path

        :rtype: bool
        :return: true if the given path is part of this SwirlFile
        """
        if path == self.path:
            return True
        else:
            for link in self.links:
                if link == path:
                    return True
        return False

    def getProvidesDict(self):
        """
        :rtype: dict
        :return: a dict which represent all the Dependecy provided by this class
                 see getDependenciesDict for the format of the dictionary
        """
        return self.getDependenciesDict(True)

    def getDependenciesDict(self, provides=False):
        """
	Return a dictionary containing the dependencies or the provides of this
        SwirlFile

        :type provides: bool
        :param provides: if provides is equal to True this function returns
                         what this SwirlFile provides instead of what it 
                         requires

        :rtype: dict
        :return: a dict where the keys are sonames of the values are
                 lists of library versions (e.g. {'libc.so.6' : 
                 ['GLIBC_2.10', 'GLIBC_2.11', 'GLIBC_2.12']})
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
        """
        returns a string represeting this SwrilFile

        :type seprator: string
        :param seprator: used to indent the output, it will be placed at the
                         beginning of each line

        :type dynamic: string
        :param dynamic: used to add a string to the first output line.
                        Currently it is used to put the --dyn-- if this
                        SwirlFile was a dynamic loaded file

        :type verbosity: int
        :param verbosity: verbosity level. 0 for the lower level 1 or 2 to get
                          more info

        :rtype: string
        :return: a detailed representation of this SwirlFile (used by the -d flags)
        """
        if verbosity == 0:
            # first we handle the short form
            return separator + str(self)+ " " + dynamic + "\n"
        retString = separator + "  " + self.path + " " + dynamic
        if verbosity > 1 and self.md5sum:
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
        """
        return a string of opened file by the given executable path execFile

        :type execFile: string
        :param execFile: used to get the list of opened file by a specific
                         executable, shared libs can open different file
                         when loaded under different executable

        :type tabs: string
        :param tabs: used to indent the output, it will be placed at the
                         beginning of each line

        :rtype: string
        :return: a string with all the opened file of this SwirlFile 
                 (used by the -d flags)
        """
        retStr = ""
        if execFile in self.openedFiles:
            retStr += tabs + "    Opened files:\n"
            for swFile in self.openedFiles[execFile]:
                retStr += tabs + "    " + str(swFile) + '\n'
        return retStr

    def __hash__(self):
        """
        This is needed to create sets of SwirlFile and avoid duplicate.
        So far the SwirlFile.path are unique among a swirl so let's use
        them for the hash
        """
        return hash(tuple(self.path) + tuple(self.links))


class Dependency(Arch):
    """
    this class reperesent a dependency declarations, it can be used to
    represent either a dependency or a provides in a swirlFile. It is an
    abstract representation of a shared library as used inside the POSIX
    loader.

    :type major: string
    :param major: it is the 'soname' of this dependency (e.g. libc.so.6, 
                  libacl.so.1, ...)

    :type minor: string
    :param minor: it is an entry in the version symbol table (e.g.
                  GLIBC_2.11, GLIBC_2.12, etc.)

    :type hwcap: string
    :param hwcap: it stores special hardware capabilities (like sse3 or avx)
                  this is a feature of the linux linker to support different
                  instruction set
    """

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
        """
        Create a dependency from a string returned by find-require find-provide

        :type string: string
        :param string: a line of output from the FingerPrint/plugin/find-requires
                       or FingerPrint/plugin/find-provides

        :rtype: :class:`FingerPrint.swirl.Dependency`
        :return: a new instance of Dependency which represent the given input
                 string
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
        """
        :rtype: string
        :return: the major of this dependency
        """
        return self.major

    def getMinor(self):
        """
        :rtype: string
        :return: the minor of this dependency
        """
        return self.minor

    def isLoader(self):
        """ 
        return true if this is the loader

        :rtype: bool
        :return: true if this dependency is a loader
        """
        if self.major.startswith("ld-"):
            return True
        return False

    def getName(self):
        """
        return a string representation of this dependency which is the
        same format used by the find-require find-provides (e.g.
        soname(minor_version)(arch)

        :rtype: string
        :return: a representation of this Dependency
        """
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

