#!/usr/bin/python
#
# LC
#
# base class for the fingerprint plugin classes
#

import os
from subprocess import PIPE, Popen
import StringIO
import re
#compatibility with python2.4
try:
    from hashlib import md5
except ImportError:
    from md5 import md5


from FingerPrint.swirl import SwirlFile, Dependency, Provide
from FingerPrint.plugins import PluginManager

"""This is the implementation for ELF files
Requirements:
 - /usr/lib/rpm/find-requires /usr/lib/rpm/find-provides from rpm
 - lsconfig in the path

TODO:
- add user path to search for libraries
- add detection of "Version References" in libraries in isDepsatisfied

"""


class ElfPlugin(PluginManager):
    """this plugin manages all ELF file format"""

    pluginName="ELF"

    #internal
    _ldconfig_64bits = "x86-64"

    _pathCache = {}
    _md5Cache = {}
 
    #may in the future we could also use 
    #objdump -p
    _RPM_FIND_DEPS=os.path.dirname( globals()["__file__"] ) + "/find-requires"
    _RPM_FIND_PROV=os.path.dirname( globals()["__file__"] ) + "/find-provides"


    @classmethod
    def isDepsatisfied(cls, dependency):
        """verify that the dependency passed can be satified on this system
        and return True if so
        """
        if cls._getPathToLibrary(dependency):
            return True
        else:
            return False


    @classmethod
    def _getPathToLibrary(cls, dependency):
        """ given a dependency it find the path of the library which provides 
        that dependency """
        soname = dependency.getBaseName()
        #for each library we have in the system
        for line in cls._getOutputAsList(["/sbin/ldconfig","-p"]):
            #if dependency is 64 and library is 64 of
            # dependency is 32 and library is 32:
            if len(line) > 0 and soname in line and \
                ( (dependency.is64bits() and cls._ldconfig_64bits in line) or \
                (dependency.is32bits() and not cls._ldconfig_64bits in line) ):
                temp = line.split('=>')
                if len(temp) == 2:
                    provider=temp[1].strip()
                    if cls._checkMinor(provider, dependency.depname):
                        return provider
        pathToScan = cls.systemPath
        if "LD_LIBRARY_PATH" in os.environ:
            #we need to scan the LD_LIBRARY_PATH too
            pathToScan += os.environ["LD_LIBRARY_PATH"].split()
        for path in pathToScan:
            provider = path + '/' + soname
            if os.path.isfile(provider) and \
                cls._checkMinor(provider, dependency.depname):
                #we found the soname and minor are there return true
                return provider
        #the dependency could not be located
        return None



    @classmethod
    def _checkMinor(cls, libPath, depName):
        """ check if libPath provides the depName (major and minor) """
        realProvider = os.path.realpath(libPath)
        for line in cls._getOutputAsList(['bash', cls._RPM_FIND_PROV], realProvider):
            if len(line) > 0 and depName in line:
                return True
        return False


    @classmethod
    def _getOutputAsList(cls, binary, inputString=None):
        """ run popen pipe inputString and return the output 
        as a list of string one for each line
        """
        p = Popen(binary, stdin=PIPE, stdout=PIPE)
        grep_stdout = p.communicate(input=inputString)[0]
        return grep_stdout.split('\n')



    @classmethod
    def _setDepsRequs(cls, swirlFile):
        """given a SwirlFile object it add to it all the dependency and all 
        the provides to it """

        #find deps
        for line in cls._getOutputAsList(['bash', cls._RPM_FIND_DEPS], swirlFile.path):
            if len(line) > 0:
                newDep = Dependency( line )
                newDep.setPluginName( cls.pluginName )
                swirlFile.addDependency( newDep )
                #i need to take the parenthesis out of the game
                tempList = re.split('\(|\)',line)
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
                # findfiles which provide the deps
                if newDep.getBaseName() in cls._pathCache :
                    #TODO do we really need to copy the list?
                    newDep.pathList += list(cls._pathCache[newDep.getBaseName()])
                    newDep.filehashes += list(cls._md5Cache[newDep.getBaseName()])
                else:
                    p = cls._getPathToLibrary( newDep )
                    if p:
                        newDep.pathList.append( p )
                        #add all the simbolik links till we hit the real file
                        while os.path.islink(newDep.pathList[-1]) :
                            p = os.readlink(newDep.pathList[-1])
                            if not os.path.isabs(p):
                                p = os.path.join(os.path.dirname(newDep.pathList[-1]), p)
                            newDep.filehashes.append( None )
                            newDep.pathList.append( p )
                        #md5
                        fileToHash = newDep.pathList[-1]
                        fd=open(fileToHash)
                        md=md5()
                        md.update(fd.read())
                        fd.close()
                        newDep.filehashes.append( md.hexdigest() )
                        #update the cache
                        cls._md5Cache[newDep.getBaseName()] = newDep.filehashes
                        cls._pathCache[newDep.getBaseName()] = newDep.pathList
            
        
        #find provides
        for line in cls._getOutputAsList(['bash', cls._RPM_FIND_PROV], swirlFile.path):
            if len(line) > 0 :
                newProv = Provide(line)
                newProv.setPluginName( cls.pluginName )
                swirlFile.addProvide(newProv)
        


    @classmethod
    def getSwirl(cls, fileName):
        """helper function given a filename it return a SwirlFile
        if the given plugin does not support the given fileName should just 
        return None
        ATT: only one plugin should return a SwirlFile for a given file
        """
        fd=open(fileName)
        magic = fd.read(4)
        if magic == '\x7f\x45\x4c\x46':
            #it's an elf see specs
            #http://www.sco.com/developers/gabi/1998-04-29/ch4.eheader.html#elfid
            swirlFile = SwirlFile( fileName )
            swirlFile.setPluginName( cls.pluginName )
            swirlFile.dyn = True
        else:
            #not an elf
            return None
        bitness = fd.read(1)
        if bitness == '\x01':
            swirlFile.set32bits()
        elif bitness == '\x02':
            swirlFile.set64bits()
        swirlFile.type = 'ELF'
        cls._setDepsRequs(swirlFile)
        return swirlFile

       
