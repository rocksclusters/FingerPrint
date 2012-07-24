#!/usr/bin/python
#
# LC
#
# base class for the fingerprint plugin classes
#

from FingerPrint.swirl import SwirlFile

"""This is the base class that implement the interface that all the plugins subclasses 
should implement
"""

class PluginMount(type):
    """
    Insipired by Marty Alchin
    http://martyalchin.com/2008/jan/10/simple-plugin-framework/
    """
    def __init__(cls, name, bases, attrs):
        if not hasattr(cls, 'plugins'):
            # This branch only executes when processing the mount point itself.
            # So, since this is a new plugin type, not an implementation, this
            # class shouldn't be registered as a plugin. Instead, it sets up a
            # list where plugins can be registered later.
            cls.plugins = {}
        else:
            # This must be a plugin implementation, which should be registered.
            # we use a dictionary here for fast lookup during dependecy verification
            cls.plugins[cls.pluginName] = cls

    def get_plugins(cls):
        return cls.plugins


class PluginManager(object):
    """
    Super class of the various plugins. All the plugins should inherit from this class

    Plugins implementing this reference should provide the following attributes:

    pluginName: this must be a unique string representing the plugin name
    

    TODO write this 

    """

    __metaclass__ = PluginMount
    systemPath = []


    @classmethod
    def addSystemPaths(self, paths):
        """add additional path to the search for dependency """
        self.systemPath += paths

    @classmethod
    def isDepsatisfied(self, dependency):
        """verify that the dependency passed can be satified on this system
        and return True if so
        """
        #let get the plugin
        #TODO catch exception key not found
        plugin = self.plugins[dependency.getPluginName()]
        return plugin.isDepsatisfied( dependency )

    @classmethod
    def getSwirl(self, fileName):
        """helper function given a filename it return a Swirl 
        if the given plugin does not support the given fileName should just 
        return None
        ATT: only one plugin should return a SwirlFile for a given file
        """
        for key, plugin in self.plugins.iteritems():
            temp = plugin.getSwirl(fileName)
            if temp != None:
                return temp
        #nobady claimed the file let's make it a Data file
        swirlFile = SwirlFile(fileName)
        swirlFile.type="Data"
        return swirlFile
 



#
# now let's import all the plugins aka all the .py file which are inside the p
# lugins directory
#

import pkgutil

for importer, package_name, _ in pkgutil.iter_modules(['FingerPrint/plugins']):
    full_package_name = 'FingerPrint.plugins.%s' % package_name
    module = importer.find_module(package_name).load_module(full_package_name)



