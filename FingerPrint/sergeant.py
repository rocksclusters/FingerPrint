#!/usr/bin/python
#
# LC
#
# read an already created swirl and check if it can be run of the current 
# system, which deps are missing, print on the screen current swirl
# 
#

import os, string

from swirl import Swirl
import utils
from FingerPrint.plugins import PluginManager
from FingerPrint.serializer import PickleSerializer
#compatibility with python2.4
try:
    from hashlib import md5
except ImportError:
    from md5 import md5




def readFromPickle(fileName):
    """helper function to get a swirl from a filename"""
    inputfd = open(fileName)
    pickle = PickleSerializer( inputfd )
    swirl = pickle.load()
    inputfd.close()
    return Sergeant(swirl)

def getShortPath(path):
    """given a full path it shorten it leaving only
    /bin/../filename"""
    if len(path.split('/')) <= 3:
        #no need to shorten
        return '"' + path + '"'
    returnValue = '"'
    if path[0] == '/':
        # absolute path name
        returnValue += '/' + path.split('/')[1]
    else:
        returnValue += path.split('/')[0]
    return returnValue + '/../' + os.path.basename(path) + '"'


#this variable is use by getHash
_isPrelink = None

def getHash(fileName, fileType):
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
    if fileType == 'ELF' and len(_isPrelink) > 0:
        #let's use prelink for the md5sum
        #TODO what if isPrelink fails
        (temp, returncode) = utils.getOutputAsList([_isPrelink, '-y', '--md5', fileName])
        if returncode == 0:
            return temp[0].split()[0]
        else:
            #undoing prelinking failed for some reasons
            pass
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
    """It reads an already created swirl and:
      - it detects if it can run on this system
      - it detects what has been changed
      - print this swirl on the screen
    """


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
        #remove duplicates
        depList = set()
        for i in self.swirl.execedFiles:
            depList |= set(i.staticDependencies)
        returnValue = True
        PluginManager.addSystemPaths(self.extraPath)
        for dep in depList:
            if not PluginManager.isDepsatisfied(dep):
                self.error.append(dep.getName())
                returnValue = False
        return returnValue

    def checkHash(self):
        """check if any dep was modified since the swirl file creation 
        (using checksuming) """
        self.error = []
        pathCache = []
        returnValue = True
        for swF in self.swirl.execedFiles:
            for dep in swF.staticDependencies:
                path = PluginManager.getPathToLibrary(dep)
                if not path or path in pathCache:
                    continue
                hash = getHash(path, dep.type)
                pathCache.append(path)
                swirlProvider = self.swirl.getSwirlFileByProv(dep)
                if not swirlProvider:
                    self.error.append("SwirlFile has unresolved dependency " + str(dep) \
                            + " the hash can not be verified")
                    returnValue = False
                if hash != swirlProvider.md5sum :
                    self.error.append(str(dep) + " wrong hash (computed " + hash \
                            + " originals " + swirlProvider.md5sum + ")")
                    returnValue = False
        return returnValue



    def printVerbose(self):
        """return a verbose representation of this swirl"""
        return self.swirl.printVerbose()


    def printMinimal(self):
        """return a minimal representation of this swirl"""
        return self.swirl.printMinimal()


    def checkDependencyPath(self, fileName):
        """return a list of SwirlFiles which requires the given fileName, if the 
        given file is nor required in this swirl it return None"""
        returnFilelist = []
        for execSwirlFile in self.swirl.execedFiles:
            for swDepFile in self.swirl.getListSwirlFilesDependent(execSwirlFile):
                if fileName in swDepFile.getPaths():
                    returnFilelist.append(execSwirlFile.path)
        return returnFilelist
        
    def getDotFile(self):
        """return a dot representation of this swirl
        """
        retString = "digraph FingerPrint {\n  rankdir=LR;nodesep=0.15; ranksep=0.1; fontsize=26;label =\""
        retString += self.swirl.name + " " + self.swirl.getDateString()
        retString += "\";\n"
        retString += "  labelloc=top;\n"
        clusterExec = []
        clusterLinker = []
        clusterPackage = []
        connections = ""
        for swirlFile in self.swirl.swirlFiles:
            clusterExec.append(getShortPath(swirlFile.path))
            for soname, versions in swirlFile.getOrderedDependencies().iteritems():
                for i in swirlFile.dependencies:
                    if i.getName().startswith(soname):
                        fileName = i.pathList[0]
                        packageName = '"' + i.packageList[-1].strip("'") + '"'
                # swirlfile -> soname
                depNameStr = '"' + soname + string.join(versions, '\\n') + '"'
                connections += '  ' + getShortPath(swirlFile.path)
                connections += ' -> ' + depNameStr + ';\n'
                # soname -> Filename
                newConnection = '  ' + depNameStr
                newConnection += ' -> ' + getShortPath(fileName) + ';\n'
                if newConnection not in connections:
                    connections += newConnection
                # filename -> packagename
                connections += '  ' + getShortPath(fileName)
                connections += ' -> ' + packageName + ';\n'
                # need to get the index of the color scheme for this package
                # which is also the index of the clusterPackage list
                colorIndex = 0
                for index, package in enumerate(clusterPackage):
                    if packageName in package:
                        # color scheme312 has 12 colors in it
                        colorIndex = (index % 12) + 1
                        break
                if colorIndex == 0:
                    # we need have a new color
                    colorIndex = (len(clusterPackage) % 12) + 1
                    clusterPackage.append(packageName + " [color=\"%d\"]"
                            % colorIndex )
                clusterLinker.append(depNameStr + " [color=\"%d\"]" % colorIndex)
                clusterLinker.append(getShortPath(fileName) + \
                        " [color=\"%d\"]" % colorIndex )
        # execution section
        retString += '  {\n'
        retString += '    rank=same;\n'
        retString += '    "Execution Domain" [shape=none fontsize=26];\n'
        retString += '    node [shape=hexagon];\n'
        retString += '    ' + string.join(clusterExec, ';\n    ') + ";\n"
        retString += "  }\n"
        # linker section
        retString += '  subgraph cluster_linker {\n'
        retString += '    label="";\n'
        retString += '    "Linker Domain" [shape=none fontsize=26];\n'
        retString += '    node [style=filled colorscheme=set312];\n'
        retString += '    ' + string.join(clusterLinker, ';\n    ') + ';\n'
        retString += "  }\n"

        # pakcage section
        retString += '  {\n'
        retString += '    rank=same;\n'
        retString += '    "Package Domain" [shape=none style="" fontsize=26];\n'
        retString += '    node [shape=box style=filled colorscheme=set312];\n'
        retString += '    ' + string.join(clusterPackage, ';\n    ') + ';\n'
        retString += '  }\n'

        retString += '  "Execution Domain" -> "Linker Domain" -> "Package Domain" [style=invis];\n'

        retString += connections
        retString += "\n}"

        return retString


    def getError(self):
        """after running check or checkHash if they returned False this 
        function return a list with the dependencies name that failed
        """
        return sorted(self.error)

       
    def getSwirl(self):
        """return the current swirl """
        return self.swirl 


