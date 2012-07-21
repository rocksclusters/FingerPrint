

import unittest
import subprocess
from FingerPrint.sergeant import *
from FingerPrint.swirl import *
from FingerPrint.serializer import PickleSerializer


class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        """setup for your unittest"""
        import sys
        sys.path.append("../")
        self.swirlfile = "tests/test.swirl"

    def test_sergeant(self):
        # test loading file in blotter
        inputfd = open(self.swirlfile)
        pickle = PickleSerializer( inputfd )
        swirl = pickle.load()
        inputfd.close()
        print "file %s loaded" % self.swirlfile
        serg=Sergeant(swirl)
        self.assertTrue( serg.check(), msg="the chekc on test.swirl failed")

        

        

if __name__ == '__main__':
    unittest.main()

