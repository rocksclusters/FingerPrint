#!/bin/bash -x
#

cd FingerPrint/
python setup.py test 2>&1
python setup.py bdist 2>&1
python setup.py sdist 2>&1
#install does not work for persmission
#python setup.py install 2>&1

