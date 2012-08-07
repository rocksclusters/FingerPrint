#!/usr/bin/python
#
# LC
#
# base class for the fingerprint plugin classes
#

import sys, os
import parser, symbol, types


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
    #TODO find this dinamically
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
    def _match(cls, tree) :
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
                        yield ".".join( [ i for t,i in  node[2][1:] if t==1 ])
    
                for item in cls._match(node) :
                    yield item


    @classmethod
    def getSwirl(cls, fileName) :
        """Given a path to a python file it return a list of dependecy"""
        returnList = []
        try :
            lis = parser.suite(file(fileName).read().rstrip().replace("\r\n","\n")).tolist()
        except SyntaxError,msg :
            #print "Not a python file"
            return None
        except :
            return None
        else :
            swirlFile = SwirlFile( fileName )
            swirlFile.setPluginName( cls.pluginName )
            swirlFile.type = cls.pluginName
            print "Plugin name ", cls.pluginName
            swirlFile.dyn = True
            for item in cls._match(lis) :
                #it is a python file
                if item not in cls._buildin_modules :
                    newDep = Dependency( "%s(%s)" % (cls._prefix,item) )
                    newDep.setPluginName( cls.pluginName )
                    swirlFile.addDependency( newDep )
        return swirlFile
    
    



       
