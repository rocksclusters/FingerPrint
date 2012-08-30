#!/usr/bin/python
#
# LC
#
# base class for the fingerprint plugin classes
#

import sys, os
import parser, symbol, types
import re


from FingerPrint.swirl import SwirlFile, Dependency
from FingerPrint.plugins import PluginManager


"""This is a plugin to check python files for their dependencies and provides
"""

# Preliminary hack to python 2.4 compatibility
def _pro( x ):
    return x[1]


class PythonPlugin(PluginManager):
    """this plugin manages only python source code file for now"""

    pluginName="python"
    _prefix = "python%u.%u" % sys.version_info[0:2]
    _buildin_modules = sys.builtin_module_names
 
    @classmethod
    def isDepsatisfied(cls, dependency):
        """verify that the dependency passed can be satified on this system
        and return True if so
        """
        #TODO implement this
        return True

                

    @classmethod
    def getSwirl(cls, fileName) :
        """Given a path to a python file it return a list of dependecy"""
        returnList = []
        try :
            f = file(fileName)
            data = f.read().rstrip().replace("\r\n","\n")
            lis = parser.suite(data).tolist()
        except SyntaxError,msg :
            #print "Not a python file"
            f.close()
            return None
        except :
            f.close()
            return None
        else :
            swirlFile = SwirlFile( fileName )
            swirlFile.setPluginName( cls.pluginName )
            swirlFile.type = cls.pluginName
            swirlFile.dyn = True
            #
            # let's check which interpreter should we use
            #
            f.seek(0)
            header = f.readline().rstrip()
            f.close()
            pythonVer = None
            if header[0:2] == '#!':
                for i in re.split(' |/|!', header):
                    if 'python' in i:
                        pythonVer = i
            if not pythonVer:
                pythonVer = cls._prefix
            for item in cls._getModules(lis) :
                newdepName = pythonVer + "(" + item + ")"
                # newdepName is not in buildin_modules and
                # it's really a new dep
                if item not in cls._buildin_modules and \
                    newdepName not in [ i.depname for i in swirlFile.dependencies ]:
                    newDep = Dependency( newdepName )
                    newDep.setPluginName( cls.pluginName )
                    #
                    # we have to find which file provides this dep
                    #
                    #TODO move to a function
                    paths = []
                    #TODO load from a differen interpreter
                    if pythonVer == 'python' or pythonVer == cls._prefix:
                        #we can use this interpreter
                        try:
                            if '.' in item:
                                # When the name variable is of the form package.module,
                                # normally, the top-level package (the name up till the
                                # first dot) is returned, not the module named by name.
                                # so we need __import__('xml.sax.handler', glob, local, 'handler')
                                module = __import__(item, globals(),
                                    locals(), item.split('.')[-1])
                            else:
                                module = __import__(item)
                        except:
                            print "Unable to import module %s, skipping..." % \
                                (item)
                            continue
                        else:
                            paths = os.path.abspath(module.__file__)
                            if paths.endswith('.pyc') or paths.endswith('.pyo'):
                                if os.path.isfile( paths[0:-1] ):
                                    paths = paths[0:-1]
                    if len(paths) > 0:
                        newDep.pathList.append( paths )
                    swirlFile.addDependency( newDep )
        return swirlFile
    


    @classmethod
    def _getModules(cls, tree) :
        """generator function it return an iterator over a list of
        string which represents the dependency"""
        for node in tree :
            if type(node) in [types.ListType, types.TupleType] :
                if node[0] == symbol.import_stmt :
                    node = _pro(node)
                    if node[1][1] == 'import' :
                        for name in [x for x in node[2][1:] if x[0] != 12  ] :
                            yield ".".join( [ i for t,i in  name[1][1:] if t==1 ])
                    elif node[1][1] == 'from' :
                        yield ".".join( [ i for t,i in  node[2][1:] if t==1 ] )
                for item in cls._getModules(node) :
                    yield item


