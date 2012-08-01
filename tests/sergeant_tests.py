

import unittest
import subprocess
import FingerPrint.sergeant
from FingerPrint.swirl import Swirl


class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        """setup for your unittest"""
        import sys
        sys.path.append("../")
        self.swirlfile = "tests/test.swirl"

    def test_sergeant(self):
        print "     -----------------------  Verifying system compatibility with sergeant   -------------------------"
        # test loading file in blotter
        print "file %s loaded" % self.swirlfile
        serg = FingerPrint.sergeant.readFromPickle(self.swirlfile)
        self.assertTrue( serg.check(), msg="The check on %s failed." 
                    % self.swirlfile)

        

        

if __name__ == '__main__':
    unittest.main()

