

import unittest
import subprocess
from FingerPrint.blotter import *
from FingerPrint.swirl import *
from FingerPrint.plugins.base import *

class TestiPlugin(unittest.TestCase):

    def setUp(self):
        """setup for your unittest"""
        import sys
        sys.path.append("../")
        self.files = ["/bin/ls", "/usr/bin/find", "/etc/passwd", 
            "/lib/libcryptsetup.so.4.0.0", "/lib/x86_64-linux-gnu/libm.so.6",
            "/lib/x86_64-linux-gnu/libm-2.15.so"]

    def test_plugin(self):
        self.swirl = Swirl("test", datetime.now())
        pl = PluginManager()
        for i in self.files:
            swirlFile = pl.getSwirl(i)
            self.swirl.addFile(swirlFile)
        print "----------- plugin test ----------------"
        print self.swirl
            

        


if __name__ == '__main__':
    unittest.main()

