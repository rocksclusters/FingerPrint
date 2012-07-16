#!/bin/python
#
# LC
#

from datetime import datetime
import StringIO

class Swirl:
    """main swirl class
    """
    def __init__(self, name, creationDate):
        self.name = name
        self.creationDate = creationDate

    def setDependencySet(self, dependencySet):
        self.dependencySet = dependencySet

    def save(self, saver):
        """this method is used to serialize this class hierarcy
        """
        saver.save(self)

    def getDate(self):
        return self.creationDate.strftime("%A, %d. %B %Y %I:%M%p")        

    def __str__( self ):
        string = self.name + " " + self.getDate() + "\n"
        string += str(self.dependencySet)
        return string
        
class DependencySet(Swirl):
    """does it make sense to have recursive dependency set?
    or should they just be a flat list?
    """ 

    def __init__(self):
        self.depSet = []

    def addDependency(self, dependency):
        self.depSet.append(Dependency(dependency))
    
    def __str__( self ):
        string=""
        for i in self.depSet:
            string += str(i) + "\n"  
        return string


class Dependency(Swirl):
    """ This class represent a single dependency
    """

    def __init__(self, name):
        self.depname = name

    def __str__( self ):
        return self.depname



class XmlSerializer:
    """this serilizes the swirl into xml
    we can have multiple classes for serializing in other format
    TODO this should be moved in another .py file
    """

    def __init__(self, fd):
        self.fd = fd

    def save(self, swirl ):
        self.fd.write("<xml>\n")
        self.fd.write("<name>" + swirl.name + "</name>\n")
        self.fd.write("<time>" + swirl.getDate() + "</time>\n")
        self.save_depset(swirl.dependencySet)
        self.fd.write("</xml>")

    def save_depset(self, dependencySet):
        self.fd.write("<depset>\n")
        for i in dependencySet.depSet:
            if isinstance(i, Dependency):
                self.fd.write("<dep>" + i.depname + "</dep>\n")
            else:
                self.save_depset(i)
        self.fd.write("</depset>\n")
    
    def read(self):
        """this should implement the read from xml
        """
        pass
            


