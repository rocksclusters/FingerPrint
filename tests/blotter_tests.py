

import unittest
import subprocess
from FingerPrint.blotter import *
from FingerPrint.swirl import *

class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        """setup for your unittest"""
        import sys
        sys.path.append("../")
        self.files = ["/bin/ls", "/usr/bin/find", "/etc/passwd", 
            "/lib/libcryptsetup.so.4.0.0", "/lib/x86_64-linux-gnu/libm.so.6",
            "/lib/x86_64-linux-gnu/libm-2.15.so"]
        pass

    def test_blotter(self):
        # test loading file in blotter
        
        b=Blotter("Test", self.files)
        print "swirl structure:\n", b.getSwirl()
        #self.assertEqual(self.seq, range(10))
        print "list of global dependecies:\n", b.getSwirl().getDependencies()
        print "list of global provides:\n", b.getSwirl().getProvides()

    def test_commandline(self):
        """ """
        outputfilename='output.swirl'
        self.assertEqual( subprocess.call(['python', './scripts/fingerprint', '-f', outputfilename] + self.files), 0,
            msg="fingerprint failed to analize the files: " + str(self.files))
        self.assertTrue( os.path.isfile(outputfilename), 
            msg="the output file %s was not created properly" % outputfilename )
        #os.remove(outputfilename)
        self.assertNotEqual(subprocess.call(['python', './scripts/fingerprint']), 0,
            msg="empty command line should fail but it did not")
        

if __name__ == '__main__':
    unittest.main()

