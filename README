
FingerPrint
===========

Fingherprint is an software tool able to analyze an application and to 
automatically save all its dependencies in a file (called Swirl) along with 
several other information.

A Swirl can then be used to understand if the given application can run on 
another system or if some of the dependencies got modified since the 
Swirl creation.




 --  INSTALL  --

The simplest way to use FingerPrint is to add to your PATH the ./bin directory
of this source code, and you will be done (on bash
export PATH=$PATH:<full_path_to_source>/bin )

To install fingerprint on your system from source you can run

 # python setup.py install

This will install FingerPrint in your python. FingerPrint consist of:
 - a bunch of python modules and submodules inside the FingerPrint module
 - a command line called fingerprint

You will need writing priviledge on some system direcotries.

To run some unittest run

 # python setup.py test

The only requirement is python 2.4 or greater.

If found on the system (they are not required), fingerprint uses:
 - prelink (to remove prelinking information from libraries and get their hash)
 - dpkg or rpm (to record package version and info regarding dependencies)


 --  USE   --

To get some help on the commnad line you can simply type:

 # fingerprint -h 

Basically there are four main actions fingerprint can do:

 1. Create a swirl from a set of input file (flag -c). In this mode
    fingerprint will scan the list of files passed on the command line
    and it will write a swirl file containing all the dependency detected 
    in the files.

 2. Display the content of a swirl file (flag -d). In this mode fingerprint 
    will print to stdout a detailed description of the input swirl. The input
    swirl can be specified with -f, or it will be the default output.swirl.

 3. Verify a swirl (flag -y). In this mode fingerprint scan the current system 
    for the dependencies listed in the input swirl and return 0 if they were 
    all found or 1 if some of then are unavailable. If verbose flag is given 
    it will print also a list of unmet depenencies.

 4. Integrity check (flag -i). In this mode fingerprint scans the system were 
    it is invoked and checks if any of the dependencies listed in the input 
    swirl have been modified since its creation (to this purpose it uses the 
    checksums stored in the swirl). It return 0 upon success or 1 in case of 
    failurer, with the verbose flag it prints also a list of modified files.


