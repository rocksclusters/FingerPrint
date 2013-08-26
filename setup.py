#!/usr/bin/python

from distutils.core import setup, Extension

#
# courtesy of Darren
# http://da44en.wordpress.com/2002/11/22/using-distutils/
#
from distutils.core import Command
from unittest import TextTestRunner, TestLoader
from glob import glob
from os.path import splitext, basename, join as pjoin, walk
import os
import sys

class TestCommand(Command):
    user_options = [ 
        # I would like to selectively run unit tests
        # TODO implement this
        ('test=', None,
         "test file to run, if not specified it will run all the file named _test.py"),
        ]


    def initialize_options(self):
        self._dir = os.getcwd()

    def finalize_options(self):
        pass

    def run(self):
        '''
        Finds all the tests modules named with the pattern tests/*_tests.py 
        Simply rename a bravo_tests.py to bravo_tosts.py to disable the file
        '''
        testfiles = [ ]
        for t in glob(pjoin(self._dir, 'tests', '*.py')):
            if not t.endswith('__init__.py') and t.endswith("tests.py"):
                testfiles.append('.'.join(
                    ['tests', splitext(basename(t))[0]])
                )

        tests = TestLoader().loadTestsFromNames(testfiles)
        t = TextTestRunner(verbosity = 2)
        result = t.run(tests)
        if not result.wasSuccessful():
            sys.exit(-1)


if os.path.exists("setup.cfg"):
    module = [Extension('FingerPrint.stacktracer',
        #these are imported from setup.cfg
        #include_dirs = [' ']
        #library_dirs = [' ']
        libraries = ['unwind-ptrace', 'unwind-x86_64', 'unwind'],
        sources = ['FingerPrint/stacktracer.c']
        )]
else:
    module = []

# read the README.rst
file = open('README.rst')
long_description = file.read()
file.close()

file = open('LICENSE')
license = file.read()
file.close()


# 
# main configuration of distutils
# 
setup(
    name = 'fingerprint-app',
    version = '0.2',
    description = 'Fingerprinting application dependencies',
    author = 'Phil Papadopoulos',
    author_email =  'philip.papadopoulos@gmail.com',
    maintainer = 'Luca Clementi',
    maintainer_email =  'luca.clementi@gmail.com',
    platforms = ['linux'],
    url = 'https://github.com/rocksclusters/FingerPrint',
    long_description = long_description,
    license = license,
    #main package, most of the code is inside here
    packages = ['FingerPrint', 'FingerPrint.plugins', 'FingerPrint.ptrace'],
    package_data = {'FingerPrint.plugins': ['find-requires', 'find-provides']},
    #package_dir = {'FingerPrint': 'FingerPrint'},
    #needs this for detecting file type
    #py_modules=['magic'],
    # readme and license files
    data_files = [('', ['README.rst', 'LICENSE', 'setup.cfg.template'])],
    ext_modules = module,
    #the command line called by users    
    scripts=['bin/fingerprint'],
    #additional command to build this distribution
    cmdclass = { 'test': TestCommand,  }
)


