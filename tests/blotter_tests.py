

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
        files = ["/bin/ls", "/usr/bin/find", "/etc/passwd", "/lib/libcryptsetup.so.4.0.0"]
        b=Blotter("Test", files)
        print "lib:", b.getSwirl()
        #self.assertEqual(self.seq, range(10))



if __name__ == '__main__':
    unittest.main()
