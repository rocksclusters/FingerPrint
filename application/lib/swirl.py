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

    def basicPrint(self):
        string = self.name + " " + self.getDate() + "\n"
        string += self.dependencySet.basicPrint()
        return string
        
class DependencySet(Swirl):
    """does it make sense to have recursive dependency set?
    or should they just be a flat list?
    """ 

    def __init__(self):
        self.depSet = []

    def addDependency(self, dependency):
        self.depSet.append(dependency)
    
    def basicPrint(self):
        string=""
        for i in self.depSet:
            string += i + "\n"  
        return string

class XmlSerializer:
    """this serilizes the swirl into xml
    we can have multiple classes for serializing in other format
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
            if type(i) is str:
                self.fd.write("<dep>" + i + "</dep>\n")
            else:
                self.save_depset(i)
        self.fd.write("</depset>\n")
        


def main():
    s = Swirl("ls", datetime.now())
    dset = DependencySet()
    s.setDependencySet(dset)
    dset.addDependency("glic 3.2")
    dset.addDependency("libcurl 3")
    dset.addDependency("libcrypt 3.2")
    dset.addDependency("bash")
    print s.basicPrint()
    
    #save xml
    output = StringIO.StringIO()
    xml = XmlSerializer(output)
    xml.save(s)
    print "XML:\n", output.getvalue()
    
    
    

if __name__ == "__main__":
    main()

