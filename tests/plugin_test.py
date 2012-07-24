

import unittest
from datetime import datetime
import sys

sys.path.append("../")
from FingerPrint.blotter import Blotter
from FingerPrint.swirl import Swirl
from FingerPrint.plugins import PluginManager
#now we can import the plugins 


class TestiPlugin(unittest.TestCase):

    def setUp(self):
        """setup for your unittest"""
        self.files = ["/bin/ls", "/usr/bin/find", "/etc/passwd", 
            "/lib/libcryptsetup.so.4.0.0", "/lib/x86_64-linux-gnu/libm.so.6",
            "/lib/x86_64-linux-gnu/libm-2.15.so", "/usr/lib/python2.7/xml/dom/minidom.py"]

    def test_plugin(self):
        self.swirl = Swirl("test", datetime.now())
        for i in self.files:
            swirlFile = PluginManager.getSwirl(i)
            self.swirl.addFile(swirlFile)
        print "----------- plugin test ----------------"
        print "plugins: ", PluginManager.get_plugins()
        print self.swirl
        print self.swirl.getDependencies()
            

        


if __name__ == '__main__':
    unittest.main()

