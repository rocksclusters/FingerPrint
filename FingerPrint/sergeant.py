#!/usr/bin/python
#
# LC
#
# read an already created swirl and check if it can be run of the current 
# system, which deps are missing, print on the screen current swirl
# 
#

import os, string, stat

from swirl import Swirl
import utils
from FingerPrint.plugins import PluginManager
from FingerPrint.serializer import PickleSerializer

#
# compatibility with python2.4
#
try:
    from hashlib import md5
except ImportError:
    from md5 import md5

#
# compatibility with python2.4
#
if "any" not in dir(__builtins__):
    from FingerPrint.utils import any


def readFromPickle(fileName):
    """
    helper function to get a swirl from a filename

    :type fileName: string
    :param fileName: a relative or absolute path to the file to read

    :rtype: :class:`FingerPrint.swirl.Swirl`
    :return: the Swirl read from the file
    """
    inputfd = open(fileName)
    pickle = PickleSerializer(inputfd)
    swirl = pickle.load()
    inputfd.close()
    serg = Sergeant(swirl)
    serg.setFilename(fileName)
    return serg

def getShortPath(path):
    """
    Given a full path it shorten it leaving only /bin/../filename

    :type path: string
    :param path: a long absolute path to the file

    :rtype: string
    :return: the shortened path
    """
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


# do we have a prelinker? 
# this variable is use by getHash and by the syscaltracer

if os.path.exists('/usr/sbin/prelink'):
	prelink = '/usr/sbin/prelink'
else:
	prelink = utils.which("prelink", "/usr/sbin")


#let's skip vairous special files
specialFolders = ["/proc/","/sys/","/tmp", "/dev/",
                "/etc/shadow", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf",
                "/etc/localtime", "/etc/hosts", "/etc/selinux", "/etc/resolv.conf",
                "/etc/fstab", "/etc/inittab", "/etc/rc", "/etc/sys", "/etc/security",
                "/etc/pam", "/etc/ntp", "/etc/issue", "/etc/rpc", "/etc/grub",
                "/etc/krb5.conf"]

def is_special_folder(path):
    """
    return true if path is to be considered special, which means it should
    be skipped from archivingi, checksumming, etc.

    :type path: string
    :param path: an absolute path to the file

    :rtype: bool
    :return: True if the given path is special
    """
    return any([ path.startswith(i) for i in specialFolders ])

def getHash(fileName, fileType):
    """
    It return a md5 checksum of the given file name. If we are running
    on a system which prelink binaries (aka RedHat based) the command
    prelink must be on the PATH

    :type fileName: string
    :param fileName: a path to the file which we want to checksum

    :type fileType: string
    :param fileType: the file type (the only recognized value is EFL for
                     triggering the prelink on RHEL base system)

    :rtype: string
    :return: an hexdadeciaml representation of the md5sum checksum
    """
    # let's skip weird stuff
    if is_special_folder(fileName):
        return ""
    if not stat.S_ISREG( os.stat(fileName).st_mode  ):
        # probably a socket, fifo, or similar
        return ""

    if fileType == 'ELF' and prelink:
        #let's use prelink for the md5sum
        #TODO what if isPrelink fails
        (temp, returncode) = utils.getOutputAsList([prelink, '-y', '--md5', fileName])
        if returncode == 0:
            return temp[0].split()[0]
        else:
            #undoing prelinking failed for some reasons
            pass
    try:
        # ok let's do standard md5sum
        fd=open(fileName)
        md=md5()
        md.update(fd.read())
        fd.close()
        return md.hexdigest()
    except IOError:
        #file not found
        return None


class Sergeant:
    """
    Given an already existent Swirl:
      - it detects if it can run on this system
      - it detects what has been changed
      - print this swirl on the screen

    :type swirl: :class:`FingerPrint.swirl.Swirl`
    :param swirl: The Swirl that we want to test

    :type extraPath: list
    :param extraPath: a list of string containing system path which should
                      be included in the search of dependencies
    """


    def __init__(self, swirl, extraPath=[]):
        self.swirl = swirl
        self.extraPath = extraPath
        self.error = []
        self.missingDeps = set()

    def setFilename(self, filename):
        """TODO remove this function"""
        self.filename = filename

    def setExtraPath(self, path):
        """
        These paths will be added to the search list when looking for
        dependency, they overwrite the extraPath passed at the constructor

        :type path: string
        :param path: a string containing a list of path separated by :
        """
        self.extraPath = path.split(':')


    def check(self):
        """
        It performs the check on the system and verifies that all the
        dependencies of this Swirl can be satisfied.

        :rtype: bool
        :return: True if the check passes False otherwise. The list of
                 missing dependencies can be retrieved with self.getError()
        """
        returnValue = True
        # this method of using rpath is not totaly correct but it's faster
        # so for the moment we have to live with this
        for swF in self.swirl.execedFiles:
            rpath = swF.rpaths + self.extraPath + utils.getLDLibraryPath(swF.env)
            for swf_dep in [swF] + self.swirl.getListSwirlFilesDependentStatic(swF):
                for dep in swf_dep.staticDependencies:
                    if not PluginManager.getPathToLibrary(dep, rpath = rpath):
                        self.missingDeps.add(dep)
                        returnValue = False
            for dynamic_dep in swF.dynamicDependencies:
                if not os.path.exists(dynamic_dep.path):
                    self.missingDeps = self.missingDeps.union(dynamic_dep.provides)
                    returnValue = False
        return returnValue

    def checkHash(self, verbose=False):
        """
        It checks if any dependency was modified since the swirl file creation
        (using checksumming) 

        :type verbose: bool
        :param verbose: if True it will generate more verbose error message

        :rtype: bool
        :return: True if the check passes False otherwise. The list of
                 modified dependencies can be retrieved with self.getError()
        """
        self.error = []
        pathCache = []
        returnValue = True
        for dep in self.swirl.getDependencies():
            path = PluginManager.getPathToLibrary(dep)
            if not path:
                # error `
                tmpStr = str(dep)
                if verbose:
                    tmpStr += " unable to find its file"
                self.error.append(tmpStr)
                returnValue = False
                continue
            if path in pathCache:
                #we already did this file
                continue
            hash = getHash(path, dep.type)
            pathCache.append(path)
            swirlProvider = self.swirl.getSwirlFileByProv(dep)
            if not swirlProvider:
                self.error.append("SwirlFile has unresolved dependency " + str(dep) \
                        + " the hash can not be verified")
                returnValue = False
            if hash != swirlProvider.md5sum :
                tmpStr = str(dep)
                if verbose:
                    tmpStr += " wrong hash (computed " + hash + " originals " + \
                            swirlProvider.md5sum + ")"
                self.error.append(tmpStr)
                returnValue = False
        return returnValue

    def searchModules(self):
        """
        It searches for missing dependencies using the 'module' command line.
        :meth:`Sergeant.check` should be called before this

        :rtype: string
        :return: with a human readable list of module which can satisfy
                 missing dependencies
        """
        # loop through all the modules
        retDict = {}
        (output, retval) = utils.getOutputAsList(["bash", "-c", "module -t avail 2>&1"])
        if retval:
            print "Unable to run module command, verify it\'s in the path."
            return ""
        for module in output :
            # in the output there are some paths! remove them e.g. "/opt/module/blabla:"
            if ':' in module:
                continue
            # remove (default)
            module = module.split("(default)")[0]
            (output, retval) = utils.getOutputAsList(["bash", "-c",
                                                "module show " + module + " 2>&1"])
            if retval:
                #print "Unable to fetch module information: \'module show " + module + "\'"
                # all module which depend on another module return 1
                pass
            for line in output:
                if 'LD_LIBRARY_PATH' in line:
                    # we found another path to scan
                    path = line.split('LD_LIBRARY_PATH')[1]
                    path = [i.strip() for i in path.split(":")] #strip
                    PluginManager.systemPath = path # update path
                    for dep in self.missingDeps:
                        if PluginManager.getPathToLibrary(dep, False):
                            #we found a candidate for this missing dependency
                            if module not in retDict:
                                retDict[module] = []
                            retDict[module].append(dep.getName())
        retStr = ""
        for mod in retDict:
            retStr += "  " + mod + " satisfies "
            num_deps = len(retDict[mod])
            if num_deps == len(self.missingDeps):
                retStr += "all "
            retStr += "" + str(num_deps) + " dependencies:\n"
            # print the deps
            retStr += "    " + "\n    ".join(retDict[mod]) + "\n"
        return retStr


    def print_swirl(self, verbosity):
        """
        return a string with the representation of this swirl

        :type verbosity: int
        :param verbosity: various verbosity level see
                          :meth:`FingerPrint.swirl.Swirl.printVerbose`

        :rtype: string
        :return: a human readable representation of this Swirl
        """
        return self.swirl.printVerbose(verbosity)


    def checkDependencyPath(self, fileName):
        """
        it returns a list of SwirlFiles which requires the given fileName, if the 
        given file is not required in this swirl it returns an empty list []

        :type fileName: string
        :param fileName: a path to a file

        :rtype: list
        :return: a list of :class:`FingerPrint.swirl.SwirlFile` required by the fileName

        """
        returnFilelist = []
        for execSwirlFile in self.swirl.execedFiles:
            for swDepFile in self.swirl.getListSwirlFilesDependentStaticAndDynamic(execSwirlFile):
                if fileName in swDepFile.getPaths():
                    returnFilelist.append(execSwirlFile.path)
        return returnFilelist
        
    def getDotFile(self):
        """
        return a dot representation of this swirl

        :rtype: string
        :return: a string with the dot representation of this swirl
        """
        clusterExec = []
        clusterSoname = set()
        clusterLinker = set()
        clusterPackage = []
        newDependencies = []
        connections = ""
        for execedSwirlFile in self.swirl.execedFiles:
            clusterExec.append( getShortPath( execedSwirlFile.path ) )
            dependenciesDict = execedSwirlFile.getDependenciesDict()
            for soname in dependenciesDict:
                # get the dep which satisfy the soname
                depSwf = self.swirl.getListSwirlFileProvide( [dependenciesDict[soname][0]] )[0]
                newDependencies.append(depSwf)
                fileName = getShortPath(depSwf.path)
                # depName is soname\nversion1\nversion2\nversion3 etc.
                depNameStr = '"' + soname  +  '"'
                # swirlfile -> soname
                connections += '  ' + getShortPath(execedSwirlFile.path)
                connections += ' -> ' + depNameStr + ';\n'
                # soname -> Filename
                newConnection = '  ' + depNameStr
                newConnection += ' -> ' + fileName + ';\n'
                if newConnection not in connections:
                    connections += newConnection
                # filename -> packagename
                if depSwf.package :
                    packageName = '"' + depSwf.package.split()[0] + '"'
                    newConnection = '  ' + fileName
                    newConnection += ' -> ' + packageName + ';\n'
                    if newConnection not in connections:
                        connections += newConnection
                else:
                    packageName = None
                colorStr = self._getColor(packageName, clusterPackage)
                # these are sets so no need to check for duplicate
                clusterSoname.add(depNameStr + colorStr)
                clusterLinker.add(fileName + colorStr )

        #TODO secondary dependencies
        #for swf in newDependencies:
            for dynDep in execedSwirlFile.dynamicDependencies:
                # create a dynamic dependencies
                fileName = getShortPath(dynDep.path)
                # swirlfile -> synDepPath
                connections += '  ' + getShortPath(execedSwirlFile.path)
                connections += ' -> ' + fileName + ';\n'
                if dynDep.package :
                    packageName = '"' + dynDep.package.split()[0] + '"'
                    newConnection = '  ' + fileName
                    newConnection += ' -> ' + packageName + ';\n'
                    if newConnection not in connections:
                        connections += newConnection
                else:
                    packageName = None
                colorStr = self._getColor(packageName, clusterPackage)
                # these are sets so no need to check for duplicate
                clusterSoname.add(depNameStr + colorStr)
                clusterLinker.add(fileName + colorStr )

        retString = "digraph FingerPrint {\n  rankdir=LR;nodesep=0.15; ranksep=0.1; fontsize=26;label =\""
        retString += self.swirl.name + " " + self.swirl.getDateString()
        if self.swirl.cmdLine :
            retString += ' \\"' + self.swirl.cmdLine.replace('"','\\"') + '\\"'
        retString += "\";\n"
        retString += "  labelloc=top;\n"
        # execution section
        retString += '  {\n'
        retString += '    rank=same;\n'
        retString += '    "Execution Domain" [shape=none fontsize=26];\n'
        retString += '    node [shape=hexagon fontsize=16];\n'
        retString += '    ' + string.join(clusterExec, ';\n    ') + ";\n"
        retString += "  }\n"
        # linker section
        retString += '  subgraph cluster_linker {\n'
        retString += '    label="";\n'
        retString += '    "Linker Domain" [shape=none fontsize=26];\n'
        retString += '    node [style=filled colorscheme=set312 fontsize=16];\n'
        retString += '    {rank=same;\n'

        retString += '      ' + string.join(clusterSoname, ';\n    ') + ';\n'
        retString += '    }\n    {rank=same;\n'
        retString += '    ' + string.join(clusterLinker, ';\n    ') + ';\n'
        retString += "    }\n  }\n"

        # pakcage section
        retString += '  {\n'
        retString += '    rank=same;\n'
        retString += '    "Package Domain" [shape=none style="" fontsize=26];\n'
        retString += '    node [shape=box style=filled colorscheme=set312 fontsize=16];\n'
        retString += '    ' + string.join(clusterPackage, ';\n    ') + ';\n'
        retString += '  }\n'

        retString += '  "Execution Domain" -> "Linker Domain" -> "Package Domain" [style=invis];\n'

        retString += connections
        retString += "\n}"

        return retString


    def _getColor(self, packageName, clusterPackage):
        """return the color number associated with the given packageName"""
        # need to get the index of the color scheme for this package
        # which is also the index of the clusterPackage list
        if not packageName:
            #no package get gray
            return " [color=\"gray\"]"
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
        colorStr = " [color=\"%d\"]" % colorIndex
        return colorStr



    def getError(self):
        """
        After running check or checkHash it return a list of the problems found

        :rtype: list
        :return: a lit of strings with all the problems encountered
        """
        return [ i.getName() for i in self.missingDeps] + self.error

       
    def getSwirl(self):
        """
        return the current swirl

        :rtype: :class:`FingerPrint.swirl.Swirl`
        :return: the current swirl
        """
        return self.swirl 


