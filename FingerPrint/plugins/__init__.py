#!/usr/bin/python
#
# LC
#
# base class for the fingerprint plugin classes
#

import os

import FingerPrint
from FingerPrint.swirl import SwirlFile


"""This is the base class that implement the interface that all the plugins subclasses 
should implement
"""

class PluginMount(type):
    """
    this is a singleton object which can return a list of all available
    plugins. All plugin available inside the FingerPrint.plugins are loaded
    inside the PluginMount when this module is loaded.

    Insipired by (or totaly copied from) Marty Alchin:
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
        """
        return the list of currently registered plugins

        :rtype: list
        :return: a list of :class:`PluginManager` registered
        """
        return cls.plugins


class PluginManager(object):
    """
    Super class of the various plugins. All plugins should inherit from
    this class.

    To implement a new Plugin you should subclass this class and provide the
    following attributes/methods:

    - :attr:`pluginName`: this must be a unique string representing the plugin name
    - :meth:`getPathToLibrary`: a class method which return a file name pointing to the
                file which can provide the given dependency
    - :meth:`getSwirl`: a class method that given a path to a file it return None if the
                file can not be handled by the given plugin or a SwirlFile
                with the dependency set if the plugin can handle the file

    """

    __metaclass__ = PluginMount
    systemPath = []
    """list of string containing the paths we should look for dependencies"""


    @classmethod
    def addSystemPaths(self, paths):
        """
        add an additional paths to the search for dependency

        :type paths: list
        :param paths: a list of string with the extra path to be added
        """
        if paths :
            self.systemPath += paths

    @classmethod
    def getSwirl(self, fileName, swirl, env = None):
        """
        helper function given a filename it return a SwirlFile. This should be
        re-implemented by the various plugins. If none of the plugins return
        a SwirlFile this method will return a 'data' SwirlFile.

        ATT: only one plugin should return a SwirlFile for a given file

        ATT2: this is a class method

        :type fileName: string
        :param fileName: a path to the new file we want to add

        :type swirl: :class:`FingerPrint.swirl.Swirl`
        :param swirl: the current Swirl object. Static dependencies of the new
                      SwirlFile are resolved first inside the Swirl and if not
                      found then they are resolved recursively invoking this
                      function and recursively added to the Swirl

        :type env: list
        :param env: a list of string with all the environment variable 
                    available to this file when it was executing. This field
                    is used only when doing dynamic tracing.

        :rtype: :class:`FingerPrint.swirl.SwirlFile`
        :return: a SwirlFile representing the given fileName. The SwirlFile 
                 should have all the static dependencies resolved (if they 
                 could be find on the system)
        """
        # if the file does not exist anymore (possible with temporary file and
        # dynamic tracing) just set it to Data
        fileName = os.path.normpath(fileName)
        if os.path.exists(fileName) and not \
		FingerPrint.sergeant.is_special_folder(fileName):
            #we call all the getSwirl method of all the plugin
            for key, plugin in self.plugins.iteritems():
                temp = plugin.getSwirl(fileName, swirl, env)
                if temp != None:
                    return temp
        #nobady claimed the file let's make it a Data file
        swirlFile = swirl.createSwirlFile(fileName)
        if os.path.isfile(fileName) and os.access(fileName, os.X_OK):
            # TODO this should be in his own plugin class
            f = open(fileName)
            if f.read(2) == '#!':
                swirlFile.executable = True
            f.close()
        return swirlFile

    @classmethod
    def getPathToLibrary(cls, dependency, useCache = True, rpath = []):
        """
        Given a dependency it find the path of the library which provides 
        that dependency

        :type dependency: :class:`FingerPrint.swirl.Dependency`
        :param dependency: the Dependency that we need to satisfy with the
                           returned library

        :type useCache: bool
        :param useCache: if true it will use a cache that will speed up a
                         lot searching for libraries

        :type rpath: list
        :param rpath: a list of string which contains extra paths that
                      we want to add during the search for the dependency
                      Generally used to add RPATH to the search path.

        :rtype: string
        :return: the path to the library which satisfy the given dependency
        """
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


