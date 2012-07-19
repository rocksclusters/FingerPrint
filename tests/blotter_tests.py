

import unittest
from FingerPrint.blotter import *
from FingerPrint.swirl import *

class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        """setup for your unittest"""
        import sys
        sys.path.append("../")
        pass

    def test_shuffle(self):
        # test loading file in blotter
        files = ["/bin/ls", "/usr/bin/find", "/etc/passwd", 
            "/lib/libcryptsetup.so.4.0.0", "/lib/x86_64-linux-gnu/libm.so.6",
            "/lib/x86_64-linux-gnu/libm-2.15.so"]
        b=Blotter("Test", files)
        print "swirl structure:\n", b.getSwirl()
        #self.assertEqual(self.seq, range(10))
        print "list of global dependecies:\n", b.getSwirl().getDependencies()
        print "list of global provides:\n", b.getSwirl().getProvides()
        



if __name__ == '__main__':
    unittest.main()
