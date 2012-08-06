#!/bin/bash -x
#

cd FingerPrint/
python setup.py test 2>&1
if [ "$?" -ne "0" ]; then
  echo "Some unit test failed. Exiting."
  exit -1
fi
python setup.py bdist 2>&1
if [ "$?" -ne "0" ]; then
  echo "Failed creating binary distribution. Exiting."
  exit -1
fi
python setup.py sdist 2>&1
if [ "$?" -ne "0" ]; then
  echo "Failed creating source distribution. Exiting."
  exit -1
fi

