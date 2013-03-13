
FingerPrint
===========

FingerPrint is a tool to analyze an arbitrary application to 
automatically list all its dependencies in a file (called Swirl) along with 
other information to describe the running process.

A Swirl can then be used to understand if the given application can run on 
another system or if some of the dependencies got modified since the 
Swirl creation.



Requirements
------------

FingerPrint will work only on a Linux system, it does not have any major 
requirement other than Python from version 2.4 up to 2.7. FingerPrint is 
currently tested on RHEL (5.x and 6.x) and (Debian 5.x and 6.x) systems.

It also requires a minimal set of core utilities (bash, sed, grep,
ldd, and objdump) but all these tools are generally present on most of
the systems.

If found on the system (they are not required), fingerprint uses:
 - prelink (to remove prelinking information from libraries and get their hash)
 - dpkg or rpm (to record package version and info regarding dependencies)


Installation
------------

The simplest way to use FingerPrint is to add to your PATH the ./bin directory
of this source code, and you will be done (on bash export PATH=$PATH:$PWD/bin )

If you want to verify your installation you can run the unittests:

    # python setup.py test

Unit-tests will generate a lot of outputs and errors but if they all succeed
at the end you will see the following lines:

    ----------------------------------------------------------------------
    Ran 4 tests in 38.870s
    
    OK


FingerPrint uses distutils so you can also run the standrad distutils procedure to install
FingerPrint on your system from source (we strongly discourag 'normal' user from using this
method though). To install fingerprint in your system python you can run:

    # python setup.py install

This will install FingerPrint in your python. FingerPrint consist of:
 - a bunch of python modules and submodules inside the FingerPrint/ directory
 - a command line called fingerprint, inside bin/ directory

You will need writing priviledge on some system direcotries. To run the dynamic tracing
you will need the local python-ptrace patched version. The python-ptrace distributed with
your distro is bugged and can not properly trace subprocesses (as per python-ptrace 0.6.5).


Use
---

To get some help on the command line you can simply type:

    # fingerprint -h

Basically there are four main actions fingerprint can do:

 1. Create a swirl from a set of input file (flag -c). In this mode
    fingerprint will scan the list of files passed on the command line
    and it will write a swirl file containing all the dependency detected 
    in the files.

 2. Display the content of a swirl file (flag -d). In this mode fingerprint
    will print to stdout a detailed description of the input swirl. The input
    swirl can be specified with -f, or it will be the default output.swirl.

 3. Query the content of a swirl file (flag -q). In this mode fingerprint
    will run a query against the specified swirl file and return 0 upon success
    or 1 when failing. If the query is run with the verbose flag (-v) it will
    also print to stdout more information regarding the query.

 4. Verify a swirl (flag -y). In this mode fingerprint scan the current system
    for the dependencies listed in the input swirl and return 0 if they were 
    all found or 1 if some of then are unavailable. If verbose flag is given 
    it will print also a list of unmet dependencies.

 5. Integrity check (flag -i). In this mode fingerprint scans the system were
    it is invoked and checks if any of the dependencies listed in the input 
    swirl have been modified since its creation (to this purpose it uses the 
    checksums stored in the swirl). It return 0 upon success or 1 in case of 
    failure, with the verbose flag it prints also a list of modified files.

Examples
--------


Create a fingerprint of your ls command:


```
clem@sirius:~/projects/FingerPrint/temp$ fingerprint -c /bin/ls
File output.swirl saved
```

By default it use output.swirl for input or output file name you can choose your own file name with "-f"

```
clem@sirius:~/projects/FingerPrint/temp$ ls -lh output.swirl
-rw-rw-r-- 1 clem clem 2.4K Feb 20 15:51 output.swirl
```

To see the list of libraries your /bin/ls depends on along with
their hash and local package name (that's what the swirl file saves)

```
clem@sirius:~/projects/FingerPrint/temp$ fingerprint -d
File name:  output.swirl
Global Dependencies:   [
    libacl.so.1()(64bit)
        /lib/x86_64-linux-gnu/libacl.so.1
        /lib/x86_64-linux-gnu/libacl.so.1.1.0 -
003978a0b6b08cd6eb82e95cdf1e199c ('libacl1 2.2.51-5ubuntu1 amd64'),
    libc.so.6()(64bit)
        /lib/x86_64-linux-gnu/libc.so.6
        /lib/x86_64-linux-gnu/libc-2.15.so -
242b7faced71bb5eb0e74487d06b7daa ('libc6 2.15-0ubuntu10.3 amd64'),
    libc.so.6(GLIBC_2.14)(64bit)
        /lib/x86_64-linux-gnu/libc.so.6
        /lib/x86_64-linux-gnu/libc-2.15.so -
242b7faced71bb5eb0e74487d06b7daa ('libc6 2.15-0ubuntu10.3 amd64'),
    libc.so.6(GLIBC_2.2.5)(64bit)
        /lib/x86_64-linux-gnu/libc.so.6
        /lib/x86_64-linux-gnu/libc-2.15.so -
242b7faced71bb5eb0e74487d06b7daa ('libc6 2.15-0ubuntu10.3 amd64'),
    libc.so.6(GLIBC_2.3)(64bit)
        /lib/x86_64-linux-gnu/libc.so.6
        /lib/x86_64-linux-gnu/libc-2.15.so -
242b7faced71bb5eb0e74487d06b7daa ('libc6 2.15-0ubuntu10.3 amd64'),
    libc.so.6(GLIBC_2.3.4)(64bit)
        /lib/x86_64-linux-gnu/libc.so.6
        /lib/x86_64-linux-gnu/libc-2.15.so -
242b7faced71bb5eb0e74487d06b7daa ('libc6 2.15-0ubuntu10.3 amd64'),
    libc.so.6(GLIBC_2.4)(64bit)
        /lib/x86_64-linux-gnu/libc.so.6
        /lib/x86_64-linux-gnu/libc-2.15.so -
242b7faced71bb5eb0e74487d06b7daa ('libc6 2.15-0ubuntu10.3 amd64'),
    librt.so.1()(64bit)
        /lib/x86_64-linux-gnu/librt.so.1
        /lib/x86_64-linux-gnu/librt-2.15.so -
43a85e435df106454dd1bbc4ba175c90 ('libc6 2.15-0ubuntu10.3 amd64'),
    librt.so.1(GLIBC_2.2.5)(64bit)
        /lib/x86_64-linux-gnu/librt.so.1
        /lib/x86_64-linux-gnu/librt-2.15.so -
43a85e435df106454dd1bbc4ba175c90 ('libc6 2.15-0ubuntu10.3 amd64'),
    libselinux.so.1()(64bit)
        /lib/x86_64-linux-gnu/libselinux.so.1 -
317e633a53dec5f82142ffa45cbabf77 ('libselinux1 2.1.0-4.1ubuntu1
amd64')]
Global Provides:   []
```

Scan the current system to verify compatibility with given swirl
i.e. either all dependencies could be resolved

```
clem@sirius:~/projects/FingerPrint/temp$ fingerprint -y
```

Verify that none of the dependencies have been modified
(it uses md5sum to check for changes).

```
clem@sirius:~/projects/FingerPrint/temp$ fingerprint -i
```

You can run the same query on the swirl

```
clem@sirius:~/projects/FingerPrint/temp$ fingerprint -q -S
/lib/x86_64-linux-gnu/librt.so.1 && echo librt is used
librt is used

clem@sirius:~/projects/FingerPrint/temp$ fingerprint -q -v -S
/lib/x86_64-linux-gnu/libcrypt.so.1 || echo libcrypt is not used
libcrypt is not used
```



Authors and Contributors
------------------------
Fingerprint is an idea of Phil Papadopoulos and it is developed by Phil and Luca
Clementi.  This work is funded by NSF under the grant #1148473.


Support or Contact
------------------
If you are having trouble with FingerPrint or if you need some help you can post an
issue or contact me at clem \a\t sdsc dot edu.

