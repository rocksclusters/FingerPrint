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
import ctypes


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
 
    #may in the future we could also use 
    #objdump -p
    _RPM_FIND_DEPS="/usr/lib/rpm/find-requires"
    _RPM_FIND_PROV="/usr/lib/rpm/find-provides"


    @classmethod
    def isDepsatisfied(cls, dependency):
        """verify that the dependency passed can be satified on this system
        and return True if so
        """
        soname = dependency.depname.split('(')[0]
        #for each library we have in the system
        for line in cls._getOutputAsList(["ldconfig","-p"]):
            #if dependency is 64 and library is 64 of
            # dependency is 32 and library is 32:
            if len(line) > 0 and soname in line and \
                ( (dependency.is64bits() and cls._ldconfig_64bits in line) or \
                (dependency.is32bits() and not cls._ldconfig_64bits in line) ):
                #line is a library with the proper soname let's check for 
                #the minor version
                temp = line.split('=>')
                if len(temp) == 2:
                    provider=temp[1].strip()
                    if cls._checkMinor(provider, dependency.depname):
                        return True
        pathToScan = cls.systemPath
        if "LD_LIBRARY_PATH" in os.environ:
            #we need to scan the LD_LIBRARY_PATH too
            pathToScan += os.environ["LD_LIBRARY_PATH"].split()
        for path in pathToScan:
            if os.path.isfile(path + '/' + soname) and \
                cls._checkMinor(path + '/' + soname, dependency.depname):
                #we found the soname and minor are there return true
                return True
        return False


    @classmethod
    def _checkMinor(cls, libPath, depName):
        """ check if libPath provides the depName (major and minor) """
        realProvider = os.path.realpath(libPath)
        for line in cls._getOutputAsList([cls._RPM_FIND_PROV], realProvider):
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
        for line in cls._getOutputAsList([cls._RPM_FIND_DEPS], swirlFile.path):
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
        #find provides
        
        for line in cls._getOutputAsList([cls._RPM_FIND_PROV], swirlFile.path):
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

       
