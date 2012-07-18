#!/bin/python
#
# LC
# 
# suports serialization of a swirl into xml (and maybe in the future other
# formats
# 

from datetime import datetime
import StringIO


"""
"""



class XmlSerializer:
    """this serilizes the swirl into xml
    we can have multiple classes for serializing in other format
    TODO I don't really like this class structure yet...
    TODO it doesnot work
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
            


