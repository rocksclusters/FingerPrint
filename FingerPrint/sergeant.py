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

def getHash(fileName, pluginName):
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
    if pluginName == 'ELF' and len(_isPrelink) > 0:
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
        depList = self.swirl.getDependencies()
        returnValue = True
        PluginManager.addSystemPaths(self.extraPath)
        for dep in depList:
            if not PluginManager.isDepsatisfied(dep):
                self.error.append(dep.depname)
                returnValue = False
        return returnValue

    def checkHash(self):
        """check if any dep was modified since the swirl file creation 
        (using checksuming) """
        self.error = []
        depList = self.swirl.getDependencies()
        returnValue = True
        for dep in depList:
            path = PluginManager.getPathToLibrary(dep)
            if not path:
                continue
            hash = getHash(path, dep.pluginName)
            if not hash in dep.hashList:
                self.error.append(dep.depname)
                returnValue = False
                print dep.depname, " computed ", hash, " originals ", dep.hashList
        return returnValue

    def checkDependencyPath(self, fileName):
        """return a list of SwirlFiles which requires the given fileName, if the 
        given file is nor required in this swirl it return None"""
        returnFilelist = []
        for swirlFile in self.swirl.swirlFiles:
            if fileName in swirlFile.getListDependenciesFiles():
                returnFilelist.append(swirlFile.path)
        return returnFilelist
        
    def getDotFile(self):
        """return a dot representation of this swirl
        """
        retString = "digraph FingerPrint {\n  rankdir=LR;label =\""
        retString += self.swirl.name + " " + self.swirl.getDateString()
        retString += "\"\n"
        clusterExec = []
        clusterDeps = []
        clusterPack = []
        connections = ""
        for swirlFile in self.swirl.swirlFiles:
            clusterExec.append(getShortPath(swirlFile.path))
            for soname, versions in swirlFile.getOrderedDependencies().iteritems():
                for i in swirlFile.dependencies:
                    if i.depname.startswith(soname):
                        fileName = i.pathList[0]
                        packageName = '"' + i.packageList[-1].strip("'") + '"'
                # swirlfile -> soname
                depNameStr = '"' + soname + string.join(versions, '\\n') + '"'
                connections += '  ' + getShortPath(swirlFile.path)
                connections += ' -> ' + depNameStr + ';\n'
                # soname -> Filename
                connections += '  ' + depNameStr
                connections += ' -> ' + getShortPath(fileName) + ';\n'
                # filename -> packagename
                connections += '  ' + getShortPath(fileName)
                connections += ' -> ' + packageName + ';\n'
                clusterDeps.append(depNameStr)
                clusterDeps.append(getShortPath(fileName))
                if packageName not in clusterPack:
                    clusterPack.append(packageName)
        # cluster section
        retString += '  subgraph cluster_execution {\n    label = "Execution Realm";\n'
        retString += '    node [shape=hexagon];\n'
        retString += '    ' + string.join(clusterExec, ';\n    ')
        retString += ";\n  }\n"
        # linker section
        retString += '  subgraph cluster_linker {\n    label = "Lynker Realm";\n'
        retString += '    ' + string.join(clusterDeps, ';\n    ')
        retString += ";\n  }\n"
        # linker packager
        retString += '  subgraph cluster_packager {\n    label = "Pakcager Realm";\n'
        retString += '    node [shape=box];\n'
        retString += '    ' + string.join(clusterPack, ';\n    ')
        retString += ";\n  }\n"
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


