#!/usr/bin/python
#
# LC
#
# using existing static analysis tool to create a swirl into memory
#

import os
import magic

from swirl import *


class Blotter:

    def __init__(self, name, fileList):
        """give a file list and a name construct a swirl into memory
        """
        self.swirl = Swirl(name, datetime.now())
        #load files from system      
        for i in fileList:
            self.loadFileFromSystem(i)
        #not try to get their dependency
        dset = DependencySet()
        self.swirl.setDependencySet(dset)
        dset.addDependency("glic 3.2")
        dset.addDependency("libcurl 3")
        dset.addDependency("libcrypt 3.2")
        dset.addDependency("bash")

    def loadFileFromSystem(self, fileName):
        """helper function to automatically load from the current system this 
        file properties (it should be called only by bloter)"""
        swirlFile = SwirlFile(fileName)
        m=magic.Magic()
        typeStr=m.from_file(fileName)
        if typeStr.startswith('ELF 64-bit LSB executable') and os.access(fileName, os.X_OK):
            #ELF 64 bit
            swirlFile.arch="x86_64"
            swirlFile.type="ELF"
            swirlFile.dyn=True
        elif typeStr.startswith('ELF 32-bit LSB executable') and os.access(fileName, os.X_OK):
            #ELF 32 bit
            swirlFile.arch="i386"
            swirlFile.type="ELF"
            swirlFile.dyn=True
        else:
            #everything else is Data
            swirlFile.type="Data"
        self.swirl.addFile(swirlFile)
       
    def getSwirl(self):
        """
        """
        return self.swirl 

