

import unittest
import subprocess
from FingerPrint.sergeant import Sergeant
from FingerPrint.swirl import Swirl
from FingerPrint.serializer import PickleSerializer


class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        """setup for your unittest"""
        import sys
        sys.path.append("../")
        self.swirlfile = "tests/test.swirl"

    def test_sergeant(self):
        print "     -----------------------  Verifying system compatibility with sergeant   -------------------------"
        # test loading file in blotter
        inputfd = open(self.swirlfile)
        pickle = PickleSerializer( inputfd )
        swirl = pickle.load()
        inputfd.close()
        print "file %s loaded" % self.swirlfile
        serg=Sergeant(swirl)
        self.assertTrue( serg.check(), msg="The check on %s failed." 
                    % self.swirlfile)

        

        

if __name__ == '__main__':
    unittest.main()

