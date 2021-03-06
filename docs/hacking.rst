Hacking
-------

This is a hacking guide intended for developer and not for final users.


Built system
============

Fingerprint uses distutils to built so the standard task can be used
to package, built, and install the software::

   ./setup.py install

To install it on the local machine (although Fingerprint can be 
installed simply by setting the PATH, see the user guide for this)::

  ./setup.py sdist 

To create a source package (which is the one used in the Fingerprint
Roll)::

  ./setup.py upload

To upload Fingerprint on the PIP. TODO add some info on how to do this.

I have created an extra command to run the unit test contained in the tests
folder (currently only 1 file contains unit tests tests/blotter_tests.py)
which can be invoked with::

  ./setup.py test


Stack tracing functionality
===========================

If you wanna built Fingerprint with the stack tracing functionality
(which is not required for its proper functioning) you need:

- gcc to compile the c code
- libunwind (minimum required version is 1.0, only Fedora 20 and 
  Ubuntu 14 have the proper library version), make sure to have the
  libunwind-devel package if you are using distro packages.

To enable the compilation of the stack tracing functionality copy the file 
setup.cfg.template into setup.cfg and insert the paths to your libunwind 
then follow the standard procedure::

  ./setup.py install 


Batlab continuous testing
=========================

The folder `batlab` contains all the file necessary to run the
unit tests on batlab at every commits. To enable that you need
to request an account on batlab login to you account, 
checkout the source code from git (checkout the repo in read
only mode) and the configure a cron job which invoke the script
inside batlab/crontab.sh to run as often as you want him to 
check the source for new commits.

This is to run it every hour::

  0 1-23/2 * * * ~/FingerPrint/FingerPrint/batlab/crontab.sh



Source code structure
=====================

The main executable is in bin/fingerprint and it takes care
of simply parsing argument and calling the various component
of the FingerPrint package. Below a list of the various sub modules
inside Fingerprint with a short description of what is their role:

- :mod:`FingerPrint.swirl`: it contains the data model. All the object used
  to represent a swirl are inside this files. The main class here
  is :class:`FingerPrint.swirl.Swirl` (used to represent a swirl), it holds references to a list
  of :class:`FingerPrint.swirl.SwirlFile`. :class:`FingerPrint.swirl.SwirlFile` 
  is a class used to keep all the info
  relative to every single file traced inside a Swirl. 
  :class:`FingerPrint.swirl.Dependency` is used
  to represent _static_ dependencies between SwirlFiles.
  Swirl contains the main methods responsible for finding SwirlFile
  Creating new SwirlFile, finding Dependencies of SwirlFile etc.

- :mod:`FingerPrint.sergeant`: it reads an already created swirl and it can
  perform several checking against the current system or display the
  swirl content. It can also be used to create a dot file to be used with
  graphviz. Basically all the display (-d) query (-q) and verify (-y) 
  options are implemented here

- :mod:`FingerPrint.blotter`: This module contains only one class which is
  responsible to creates a swirl file starting from, a list of binaries,
  a command lines that we want to execute and trace, or a PID.
  It uses the plugin manager (FingerPrint.plugin) to analize each file.
  When running a dynamic tracing it uses the (FingerPrint.syscalltracer)
  module to do the ptracing work.

- :mod:`FingerPrint.plugins`: it is a plugable architecture which should support
  different file types (at the moment only an elf is implemented
  :class:`FingerPrint.plugins.elf.ElfPlugin`). Each plugin
  should subclass the class :class:`FingerPrint.plugins.PluginManager` and
  implement two methods :meth:`FingerPrint.plugins.PluginManager.getSwirl` given
  a file path create a SwirlFile and add it to the swirl and return it.
  If the file is already in the swirl return it (do not duplicate it).
  :meth:`FingerPrint.plugins.PluginManager.getPathToLibrary` should return 
  a path to a shared library on the system given a dependency. At the moment
  it tries to imitate the Linux dynamic loader.

- :mod:`FingerPrint.syscalltracer`: is in charge of ptracing a command line and
  if available use the strac tracing functionality

- :mod:`FingerPrint.ptrace`: a bunch of classes taken from python-ptrace used
  to wrap ptrace system call, they are used only by syscalltracer for
  dynamic tracing

- :mod:`FingerPrint.composer`: is a module which takes care of composing a
  roll and of creating a Swirl archive. It has two classes
  :class:`FingerPrint.composer.Archiver`, which is used to create archive
  (-r flag), and :class:`FingerPrint.composer.Roller` which supports composing
  Rolls (-m flag).

- :mod:`FingerPrint.utils`: some simple general function which are used all
  over. Functions to fork external program and get their output,
  functions to get system ``LD_LIBRARY_PATH`` paths etc.

- :mod:`FingerPrint.serializer`: it contains only one class 
  :class:`FingerPrint.serializer.PickleSerializer` which is in charge
  of serializing and deserializing a swirl into a file. All the other
  module uses this class to read and write a Swirl.
  To make a XML serializer it is necessary to modify only this class

- remapper: this directory contains the source code for the remapper
  remapper is the process which is used when porting application using
  the -z flag. It is in charge of remapping all the open system call
  using the configuration file ``/etc/fp_mapping``
