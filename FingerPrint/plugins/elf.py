#!/usr/bin/python
#
# LC
#
# base class for the fingerprint plugin classes
#

import os
import magic
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
        try:
            #TODO this verify only the soname we need to check for version too!
            p = Popen(["ldconfig","-p"], stdin=PIPE, stdout=PIPE)
            grep_stdout = p.communicate(input=None)[0]
            for line in grep_stdout.split('\n'):
                #dependency is 64 and library is 64
                #or dependency is 32 and library is 32
                if len(line) > 0 and soname in line and \
                    ( (dependency.is64bits() and cls._ldconfig_64bits in line) or \
                    (dependency.is32bits() and not cls._ldconfig_64bits in line) ):
                    temp = line.split('=>')
                    if len(temp) == 2:
                        provider=temp[1].strip()
                        if cls._verifyFindProvides(provider, dependency.depname):
                            return True
            return False
        except OSError:
            print "Error locating ldconfig"
            return False


    @classmethod
    def _verifyFindProvides(cls, provider, requirement):
        """
        """
        fixedProvider = cls._readlinkabs(provider)
        p = Popen([cls._RPM_FIND_PROV], stdin=PIPE, stdout=PIPE)
        grep_stdout = p.communicate(input=fixedProvider)[0]
        for line in grep_stdout.split('\n'):
            if len(line) > 0 and requirement in line:
                return True
        return False
                

    @classmethod
    def _readlinkabs(cls, l):
        """
        If l is a symlink it returns an absolute path for the destination 
        if not simply return l
        Used to find the real library path not the symbolic lynk
        """
        if not os.path.islink(l) :
            return l
        p = os.readlink(l)
        if os.path.isabs(p):
            return p
        return os.path.join(os.path.dirname(l), p)
        

    @classmethod
    def _setDepsRequs(cls, swirlFile):
        """given a SwirlFile object it add to it all the dependency and all 
        the provides to it """

        #find deps
        p = Popen([cls._RPM_FIND_DEPS], stdin=PIPE, stdout=PIPE)
        grep_stdout = p.communicate(input=swirlFile.path)[0]
        for line in grep_stdout.split('\n'):
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
        p = Popen([cls._RPM_FIND_PROV], stdin=PIPE, stdout=PIPE)
        grep_stdout = p.communicate(input=swirlFile.path)[0]
        for line in grep_stdout.split('\n'):
            if len(line) > 0 :
                newProv = Provide(line)
                newProv.setPluginName( cls.pluginName )
                swirlFile.addProvide(newProv)
        


    @classmethod
    def getSwirl(cls, fileName):
        """helper function given a filename it return a Swirl 
        if the given plugin does not support the given fileName should just 
        return None
        ATT: only one plugin should return a SwirlFile for a given file
        """
        m=magic.Magic()
        typeStr=m.from_file( fileName )
        #for now all the files are dynamic
        if typeStr.startswith( 'ELF ' ):
            swirlFile = SwirlFile( fileName )
            swirlFile.setPluginName( cls.pluginName )
            swirlFile.dyn = True
        else:
            #this is not our business
            return None
        #do we really need this?
        if typeStr.startswith('ELF 64-bit LSB executable'): #and os.access(fileName, os.X_OK):
            #ELF 64 bit
            swirlFile.set64bits()
            swirlFile.setExecutable()
        elif typeStr.startswith('ELF 32-bit LSB executable'):
            #ELF 32 bit
            swirlFile.set32bits()
            swirlFile.setExecutable()
        elif typeStr.startswith('ELF 64-bit LSB shared object'):
            #shared library 64
            swirlFile.set64bits()
            swirlFile.setShared()
        elif typeStr.startswith('ELF 32-bit LSB shared object'):
            #shared library 32
            swirlFile.set32bits()
            swirlFile.setShared()
        #add deps and provs
        cls._setDepsRequs(swirlFile)
        return swirlFile

       
