#!/usr/bin/python
#
# LC
#
# base class for the fingerprint plugin classes
#

import os
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
    Super class of the various plugins. All the plugins should inherit from 
    this class

    Plugins implementing this reference should provide the following 
    attributes/methods:

    pluginName: this must be a unique string representing the plugin name
    getPathToLibrary: a classmethod which return a file name pointing to the 
                file which can provide the given dependnecy
    getSwirl: a classmethod that given a path to a file it return None if the 
                file can not be handled by the given plugin or a SwirlFile 
                with the dependency set if the plugin can handle the file
    
    """

    __metaclass__ = PluginMount
    systemPath = []


    @classmethod
    def addSystemPaths(self, paths):
        """add additional path to the search for dependency """
        if paths :
            self.systemPath += paths

    @classmethod
    def getSwirl(self, fileName, swirl):
        """helper function given a filename it return a SwirlFile
        if the given plugin does not support the given fileName should just 
        return None
        ATT: only one plugin should return a SwirlFile for a given file
        """
        # if the file does not exist anymore (possible with temporary file and
        # dynamic tracing) just set it to Data
        fileName = os.path.normpath(fileName)
        if os.path.exists(fileName) :
            #we call all the getSwirl method of all the plugin
            for key, plugin in self.plugins.iteritems():
                temp = plugin.getSwirl(fileName, swirl)
                if temp != None:
                    return temp
        #nobady claimed the file let's make it a Data file
        swirlFile = swirl.createSwirlFile(fileName)
        return swirlFile

    @classmethod
    def getPathToLibrary(cls, dependency, useCache = True, rpath = []):
        """ given a dependency it find the path of the library which provides 
        that dependency """
        plugin = cls.plugins[dependency.type]
        return plugin.getPathToLibrary(dependency, useCache, rpath)


#
# now let's import all the plugins aka all the .py file which are inside the
# plugins directory
#

import pkgutil
import os
import sys
import logging

logger = logging.getLogger('fingerprint')


if hasattr(pkgutil,'iter_modules'):              #line added
    for importer, package_name, _ in pkgutil.iter_modules(globals()["__path__"]):
        full_package_name = 'FingerPrint.plugins.%s' % package_name
        module = importer.find_module(package_name).load_module(full_package_name)
else:
    # in python 2.4 pkgutil does not have a iter_modules function :-(
    for pth in globals()["__path__"]:
        for mod_path in sorted(os.listdir(pth)):
            init_py = os.path.join(pth, mod_path)
            if mod_path.endswith('.py') and mod_path != '__init__.py' \
                and os.path.isfile(init_py): 
                nm = "FingerPrint.plugins.%s" % mod_path.split('.py')[0]
                try:
                    __import__(nm)
                except:
                    logger.error("Failed to import module %s" % nm)
                    pass


