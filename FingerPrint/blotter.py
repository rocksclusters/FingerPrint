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
from FingerPrint.plugins import PluginManager




"""The getDependencies functions given a swirl file the have to figure out 
which are the dependencies of the file
"""

class Blotter:

    def __init__(self, name, fileList):
        """give a file list and a name construct a swirl into memory """
        self.swirl = Swirl(name, datetime.now())
        for i in fileList:
            swirlFile = PluginManager.getSwirl(i)
            self.swirl.addFile(swirlFile)

       
    def getSwirl(self):
        """return the current swirl """
        return self.swirl 





