#!/usr/bin/python
#
# LC
#
# base class for the fingerprint plugin classes
#

import os

from FingerPrint.swirl import SwirlFile, Dependency
from FingerPrint.plugins import PluginManager


"""This is a plugin to check python files for their dependencies and provides
"""


class PythonPlugin(PluginManager):
    """this plugin manages only python source code file for now"""

    pluginName="python"
 
    @classmethod
    def isDepsatisfied(self, dependency):
        """verify that the dependency passed can be satified on this system
        and return True if so
        """
        #TODO implement this
        
        return True

        

    @classmethod
    def setDepsRequs(self, fileName):
        """given a fileName pointing to a python script it returns a swirlFile 
        with all the dependency and provide associated with the fileName
        """
        swirlFile = SwirlFile( fileName )
        swirlFile.setPluginName( self.pluginName )
        swirlFile.dyn = True
        #find deps
        fd=open(fileName)
        #this is as quick and as dirty as it could be
        for line in fd:
            if 'import ' in line and not '"' in line:
                #this is an import line
                #TODO this is not sufficient but it will get me started
                newDep = Dependency( line.strip() )
                newDep.setPluginName( self.pluginName )
                swirlFile.addDependency( newDep )
        #TODO add provide
        return swirlFile

                

    @classmethod
    def getSwirl(self, fileName):
        """helper function given a filename it return a Swirl 
        if the given plugin does not support the given fileName should just 
        return None
        ATT: only one plugin should return a SwirlFile for a given file
        """
        #python script
        if fileName.endswith('.py'):
            return self.setDepsRequs(fileName)
        #let's check more accurately
        fd=open(fileName)
        for line in fd:
            if line.startswith('#!') and 'python' in line:
                #ok this is a python script
                fd.close()
                return self.setDepsRequs(fileName)
        fd.close()
        return None

       
