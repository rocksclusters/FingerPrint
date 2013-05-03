
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

To invoke unit-tests run

    # python setup.py test

Unit-tests will generate a lot of outputs and errors but if they all succeed
at the end you will see the following lines:

    ----------------------------------------------------------------------
    Ran 4 tests in 38.870s
    
    OK


FingerPrint uses distutils so you can also run the standrad distutils procedure to install
FingerPrint on your system from source (we strongly discourag 'normal' user from using this
method though). To install fingerprint in your system from source you can run:

    # python setup.py install

This will install FingerPrint within your Python environment. You might need writing 
privilege on system directories for such installation.

FingerPrint consist of:
 - a bunch of python modules and submodules inside the FingerPrint/ directory
 - a command line called fingerprint, inside bin/ directory


Use
---

To get some help on the command line you can simply type:

    # fingerprint -h

Basically there are four main actions fingerprint can do (-c create, -d disaply,
-q query, and -y verify):

 1. Create a swirl from a set of input file (flag -c) or with dynamic tracing.
    In this mode fingerprint will scan the list of files passed on the command
    line or it will (-x) trace the execution of the command specified to output
    a swirl file containing the dependencies fingerprint of the given input.

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
    it will print also a list of unmet dependencies. Above the verify it is also
    possible to perform an integrity check. In this mode fingerprint scans the
    system where invoked and checks if any of the dependencies listed in the
    input swirl have been modified since its creation (to this purpose it uses
    the checksums stored in the swirl). It return 0 upon success or 1 in case of
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
Swirl 2013-03-27 10:22
 -- File List -- 
  /bin/ls
    /lib/x86_64-linux-gnu/ld-2.15.so
    /lib/x86_64-linux-gnu/libacl.so.1.1.0
    /lib/x86_64-linux-gnu/libc-2.15.so
    /lib/x86_64-linux-gnu/librt-2.15.so
    /lib/x86_64-linux-gnu/libselinux.so.1
    /lib/x86_64-linux-gnu/libattr.so.1.1.0
    /lib/x86_64-linux-gnu/libpthread-2.15.so
    /lib/x86_64-linux-gnu/libdl-2.15.so
```

Scan the current system to verify compatibility with given swirl
i.e. either all dependencies could be resolved

```
clem@sirius:~/projects/FingerPrint/temp$ fingerprint -y
```

Verify that none of the dependencies have been modified
(it uses md5sum to check for changes).

```
clem@sirius:~/projects/FingerPrint/temp$ fingerprint -yi
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

Dynamic tracing
---------------
FingerPrint can dynamically trace a running process to properly detect dynamic
dependencies.  To this extent it uses the posix ptrace system call and it can
trace spwaned processes as well.

Dynamic tracing can trace dynamically loaded shared libraries and opened files.
If FingerPrint is compiled with stacktracer support (see blelow, TODO write doc)
it can also detect which shared library initiated the open syscall. To dynamically
trace a program run fingperprint with the '-c -x' flags:

```
clem@sirius:~/projects/FingerPrint/temp$ fingerprint -c -x xeyes
The fingerprint process 16131 going to trace 16134
The process  16134  exited
Tracing terminated successfully
File output.swirl saved
```

When disaplying a Swirl created with the dynamics tracing it include information
regarding open files and dynamically loaded libraries.

```
clem@sirius:~/projects/FingerPrint/temp$ fingerprint -d
File name:  output.swirl
Swirl 2013-05-03 12:00
 -- File List --
  /usr/bin/xeyes
    /lib/x86_64-linux-gnu/ld-2.15.so
    /lib/x86_64-linux-gnu/libc-2.15.so
      Opened files:
        /proc/meminfo
        /usr/lib/locale/locale-archive
    /lib/x86_64-linux-gnu/libm-2.15.so
    /usr/lib/x86_64-linux-gnu/libX11.so.6.3.0
      Opened files:
        /usr/share/X11/locale/C/XLC_LOCALE
        /usr/share/X11/locale/locale.dir
        /usr/share/X11/locale/locale.alias
        /usr/share/X11/locale/en_US.UTF-8/XLC_LOCALE
    /usr/lib/x86_64-linux-gnu/libXext.so.6.4.0
    /usr/lib/x86_64-linux-gnu/libXmu.so.6.2.0
    /usr/lib/x86_64-linux-gnu/libXrender.so.1.3.0
    /usr/lib/x86_64-linux-gnu/libXt.so.6.0.0
    /lib/x86_64-linux-gnu/libdl-2.15.so
    /usr/lib/x86_64-linux-gnu/libxcb.so.1.1.0
    /usr/lib/x86_64-linux-gnu/libICE.so.6.3.0
    /usr/lib/x86_64-linux-gnu/libSM.so.6.0.1
    /usr/lib/x86_64-linux-gnu/libXau.so.6.0.0
      Opened files:
        /home/clem/.Xauthority
    /usr/lib/x86_64-linux-gnu/libXdmcp.so.6.0.0
    /lib/x86_64-linux-gnu/libuuid.so.1.3.0
    /usr/lib/x86_64-linux-gnu/libXcursor.so.1.0.2 --(Dyn)--
    /usr/lib/x86_64-linux-gnu/libXfixes.so.3.1.0 --(Dyn)--

```


Authors and Contributors
------------------------
Fingerprint is an idea of Phil Papadopoulos and it is developed by Phil and Luca
Clementi.  This work is funded by NSF under the grant #1148473.


Support or Contact
------------------
If you are having trouble with FingerPrint or if you need some help you can post an
issue or contact me at clem \a\t sdsc dot edu.

