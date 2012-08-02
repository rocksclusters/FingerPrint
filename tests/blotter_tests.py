

import unittest
import subprocess
import os
from datetime import datetime


from FingerPrint.plugins import PluginManager
from FingerPrint.blotter import Blotter
from FingerPrint.swirl import Swirl
import FingerPrint.sergeant


class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        """setup for your unittest"""
        import sys
        sys.path.append("../")
        #TODO find a better way to find filelist
        self.files = ["/bin/ls", "/usr/bin/find", "/etc/passwd", 
            "/lib/libcryptsetup.so.4.0.0", "/lib/x86_64-linux-gnu/libm.so.6",
            "/lib/x86_64-linux-gnu/libm-2.15.so"]
        self.swirlfile = "tests/test.swirl"
        self.availablePlugin = 2


    def test_plugin(self):
        print "     -----------------------     Testing pluging manager via API  -------------------------"
        self.swirl = Swirl("test", datetime.now())
        for i in self.files:
            swirlFile = PluginManager.getSwirl(i)
            self.swirl.addFile(swirlFile)
        p = PluginManager.get_plugins()
        print "plugins: ", p
        self.assertEqual(len(p), self.availablePlugin,
            msg="Plugin manager did not load all the available plugins (available %d, detected %d) " 
            % (len(p) , self.availablePlugin) )
            


    def test_sergeant(self):
        print "     -----------------------     Verifying sergeant via API     -------------------------"
        # test loading file in blotter
        print "file %s loaded" % self.swirlfile
        serg = FingerPrint.sergeant.readFromPickle(self.swirlfile)
        self.assertTrue( serg.check(), msg="API: creating sergeant from %s failed." 
                % self.swirlfile)

    def test_blotter(self):
        # test loading file in blotter
        print "     -----------------------     Creating a blotter via API     -------------------------"
        b=Blotter("Test", self.files)
        self.assertIsNotNone(b.getSwirl())
        self.assertTrue( len(b.getSwirl().getDependencies()) > 0, 
                msg="API: blotter could not find any dependency")
        self.assertTrue( len(b.getSwirl().getProvides()) > 0, 
                msg="API: blotter could not find any provides")


    def test_commandline(self):
        """ """
        #test empty command line
        print "     -----------------------     Running fingerprint command line   -------------------------"
        self.assertNotEqual(subprocess.call(['python', './scripts/fingerprint']), 0,
            msg="fingerprint: empty command line should fail but it did not")
        #lets create a command wtih input file on the command line with default output filename
        outputfilename='output.swirl'
        self.assertEqual( 
            subprocess.call(['python', './scripts/fingerprint', '-c'] + self.files), 0,
            msg="fingerprint-create: failed to analize the files: " + str(self.files))
        self.assertTrue( os.path.isfile(outputfilename), 
            msg="fingerprint-create: the output file %s was not created properly" % outputfilename )
        os.remove(outputfilename)
        filelist='filelist'
        fd=open(filelist,'w')
        for i in self.files:
            fd.write(i + '\n')
        fd.close()
        self.assertEqual( 
            subprocess.call(['python', './scripts/fingerprint', '-c', '-f', outputfilename, '-l', filelist]), 0,
            msg="fingerprint-create: failed to load filelist: " + filelist)
        self.assertTrue( os.path.isfile(outputfilename), 
            msg="fingerprint-create: the output file %s was not created properly" % outputfilename )
        os.remove(outputfilename)


if __name__ == '__main__':
    unittest.main()

