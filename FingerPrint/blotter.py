#!/usr/bin/python
#
# LC
#
# using existing static analysis tool to create a swirl into memory
#

from datetime import datetime

from swirl import Swirl
from FingerPrint.plugins import PluginManager

import os


"""The getDependencies functions given a swirl file the have to figure out 
which are the dependencies of the file
"""

class Blotter:

    def __init__(self, name, fileList):
        """give a file list and a name construct a swirl into memory """
        self.swirl = Swirl(name, datetime.now())
        for i in fileList:
            if os.path.isfile(i):
                swirlFile = PluginManager.getSwirl(i)
                self.swirl.addFile(swirlFile)
            elif os.path.isdir(i):
                pass
            else:
                raise IOError("The file %s cannot be opened." % i)
                

       
    def getSwirl(self):
        """return the current swirl """
        return self.swirl 





