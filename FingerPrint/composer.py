#!/usr/bin/python
#
# LC
#
# create archives an archive from a swirl and create rolls from an archive
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
if "any" not in dir(__builtins__):
    from FingerPrint.utils import any



class Archiver:
    """It reads an already created swirl and:
      - it detects if it can run on this system
      - it detects what has been changed
      - print this swirl on the screen
    """


    def __init__(self, swirl_filename, archive_filename):
        """ """
        self.swirl_filename = swirl_filename
        self.archive_filename = archive_filename
        self.errors = None

    def archive(self):
        """        """
        return True


    def getError(self):
        """        """
        return self.errors

