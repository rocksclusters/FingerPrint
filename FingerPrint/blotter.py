#!/usr/bin/python
#
# LC
#
# using existing static analysis tool to create a swirl into memory
#

import os
import magic
from subprocess import PIPE, Popen
import StringIO
import re

from swirl import *


#may in the future we could also use 
#objdump -p
RPM_FIND_DEPS="/usr/lib/rpm/find-requires"
RPM_FIND_PROV="/usr/lib/rpm/find-provides"



"""The getDependencies functions given a swirl file the have to figure out 
which are the dependencies of the file
"""

def getDependencies_ELF_exe(swirlFile):
    #same stuff as ELF_sha
    getDependencies_ELF_sha(swirlFile)

def getDependencies_ELF_sha(swirlFile):
    """find dependencies and provides for for elf files"""
    #find deps
    p = Popen([RPM_FIND_DEPS], stdin=PIPE, stdout=PIPE)
    grep_stdout = p.communicate(input=swirlFile.path)[0]
    for line in grep_stdout.split('\n'):
        if len(line) > 0:
            newDep = Dependency(line)
            swirlFile.addDependency(newDep)
            #i need to take the parenthesis out of the game
            tempList = re.split('\(|\)',line)
            if len(tempList) > 2:
                #set the 32/64 bits 
                #probably unecessary
                if tempList[3].find("64bit") >= 0 :
                    newDep.set64bits()
                elif tempList[3].find("32bit") >= 0 :
                    newDep.set32bits()
    #find provides
    p = Popen([RPM_FIND_PROV], stdin=PIPE, stdout=PIPE)
    grep_stdout = p.communicate(input=swirlFile.path)[0]
    for line in grep_stdout.split('\n'):
        if len(line) > 0 :
            newProv = Provide(line)
            swirlFile.addProvide(newProv)
    


def setDependencies(swirlFile):
    """pass a swirlFile return a dependencySet """
    functionName = "getDependencies_" + swirlFile.type
    #TODO add checking
    import sys
    thismodule = sys.modules[__name__]
    function = getattr(thismodule, functionName)
    function(swirlFile)


class Blotter:

    def __init__(self, name, fileList):
        """give a file list and a name construct a swirl into memory """
        self.swirl = Swirl(name, datetime.now())
        #load files from system      
        for i in fileList:
            self.loadFileFromSystem(i)
        #not try to get their dependency
        self.findDependencies()


    def loadFileFromSystem(self, fileName):
        """helper function given a filename it load that filename into the 
        current swirl with its properties"""
        swirlFile = SwirlFile(fileName)
        m=magic.Magic()
        typeStr=m.from_file(fileName)
        #TODO fix this
        #for now all the files are dynamic
        if typeStr.startswith('ELF 64-bit LSB executable'): #and os.access(fileName, os.X_OK):
            #ELF 64 bit
            swirlFile.set64bits()
            swirlFile.setExecutable()
            swirlFile.dyn=True
        elif typeStr.startswith('ELF 32-bit LSB executable'):
            #ELF 32 bit
            swirlFile.set32bits()
            swirlFile.setExecutable()
            swirlFile.dyn=True
        elif typeStr.startswith('ELF 64-bit LSB shared object'):
            #shared library 64
            swirlFile.set64bits()
            swirlFile.setShared()
            swirlFile.dyn=True
        elif typeStr.startswith('ELF 32-bit LSB shared object'):
            #shared library 32
            swirlFile.set32bits()
            swirlFile.setShared()
            swirlFile.dyn=True
        else:
            #everything else id Data
            swirlFile.type="Data"
        self.swirl.addFile(swirlFile)

       
    def getSwirl(self):
        """return the current swirl """
        return self.swirl 


    def findDependencies(self):
        """file must be already loaded into swirl """
        for i in self.swirl.getBinaryFiles():
            setDependencies(i)






