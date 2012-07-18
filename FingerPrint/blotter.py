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



"""The getDependencies functions given a swirl file the have to figure out 
which are the dependencies of the file
"""

def getDependencies_ELF_exe(swirlFile):
    #same stuff
    return getDependencies_ELF_sha(swirlFile)

def getDependencies_ELF_sha(swirlFile):
    """find dinamic libryries for elf files"""
    depList = []
    inputBuffer = StringIO.StringIO(swirlFile.path)
    outputBuffer = StringIO.StringIO()
    p = Popen([RPM_FIND_DEPS], stdin=PIPE, stdout=PIPE)
    grep_stdout = p.communicate(input=swirlFile.path)[0]
    for line in grep_stdout.split('\n'):
        #i need to take the parenthesis out of the game
        tempList = re.split('\(|\)',line)
        if len(tempList) > 2:
            newDep = Dependency(tempList[0])
            #there is also tempList[1] but I don't know what to do with it yet
            if tempList[3].find("64bit") >= 0 :
                newDep.set64bits()
            elif tempList[3].find("32bit") >= 0 :
                newDep.set32bits()
            if len(tempList[1]) > 0:
                newDep.symbolVersion = tempList[1]
            depList.append(newDep)
    return depList


def getDependencies(swirlFile):
    """pass a swirlFile return a dependencySet """
    functionName = "getDependencies_" + swirlFile.type
    #TODO add checking
    import sys
    thismodule = sys.modules[__name__]
    function = getattr(thismodule, functionName)
    return function(swirlFile)


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
            #everything else is Data
            swirlFile.set64bits()
            swirlFile.setShared()
            swirlFile.dyn=True
        elif typeStr.startswith('ELF 64-bit LSB shared object'):
            #everything else is Data
            swirlFile.set32bits()
            swirlFile.setShared()
            swirlFile.dyn=True
        else:
            swirlFile.type="Data"
        self.swirl.addFile(swirlFile)

       
    def getSwirl(self):
        """return the current swirl """
        return self.swirl 


    def findDependencies(self):
        """file must be already loaded into swirl """
        for i in self.swirl.getBinaryFiles():
            depList = getDependencies(i)
            self.swirl.addDependencies(depList)






