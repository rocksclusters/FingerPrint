===========
FingerPrint
===========

FingerPrint is a software tool which can analyze arbitrary lists of binaries
and save all their dependencies information in a file (called Swirl) along
with other information.

A Swirl can then be used to understand if the given application can run on
another system or if some of the dependencies got modified since the
Swirl creation. Swirl can also be used to deploy the traced application
on a Rocks cluster.


Requirements
------------

FingerPrint will work only on a Linux system, it does not have any major 
requirement other than Python from version 2.4 up to 2.7. FingerPrint is 
currently tested on RHEL (5.x and 6.x) and (Debian 5.x and 6.x) systems.

It also requires a minimal set of core utilities (bash, sed, grep,
ldd, and objdump) but all these tools are generally present on most of
the systems.

If found on the system (they are not required), fingerprint uses:

- prelink (to remove pre-linking information from libraries and get their hash)
- dpkg or rpm (to record package version and info regarding dependencies)

FingerPrint comes with a stack tracing facility that can be used to determine
which shared library opens a file. The stack tracing module is not required for
the proper functioning. To compile the module you will need libunwind
shared libraries (version 0.99 comes with libunwind-ptrace compiled statically
so it does not work :-(). The stack tracing facility is written in C, so it
requires gcc.


Installation
------------

The simplest way to use FingerPrint is to checkout the source code

::

  # git clone https://github.com/rocksclusters/FingerPrint.git

and then add to your ``PATH`` the ``./bin`` directory of the source code

::

  # cd FingerPrint
  # export PATH=$PATH:$PWD/bin

After this steps you can start to use fingerprint. The following steps are
only required for advanced users. To invoke unit-tests run:

::

  # python setup.py test

Unit-tests generate a lot of outputs and errors but if they all succeed at the
end you will see the following lines:

::
    
  Ran 4 tests in 38.870s
   
  OK


If you want to install FingerPrint on your system python path you can follow the
standard `distutils <http://docs.python.org/2/install/index.html>`_ procedure.
To properly compile the stack tracing facility copy the file ``setup.cfg.template``
into ``setup.cfg`` and insert the paths to libunwind before installing Fingerprint.
After that run:

::

  # python setup.py build
  # python setup.py install

This installs FingerPrint in your Python environment. You might need writing
privilege on system directories for such installation.

FingerPrint consists of:

- a bunch of python modules and submodules inside the ``FingerPrint/`` directory
- a command line python script called fingerprint, inside ``bin/`` directory


Use
---

To get some help on the command line you can simply type:

::

  # fingerprint -h

Basically there are four main actions fingerprint can do (-c create, -d display,
-q query, and -y verify):

1. Create a swirl from a set of input file (flag -c) or with dynamic tracing.
   In this mode fingerprint will scan the list of files passed on the command
   line or it will (-x) trace the execution of the command specified to output
   a swirl file containing the dependencies fingerprint of the given input.
   This mode can also create a "swirl archive" (-r) which is nothing else than
   a tar.gz containing the swirl and all the file referenced by it.
   Using the create flag it is also possible to create a Rocks Cluster roll
   (flag -m), which will install the software described in the given "swirl
   archive" on all the nodes of a rocks cluster.

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


::

 clem@sirius:~/projects/FingerPrint/temp$ fingerprint -c /bin/ls
 File output.swirl saved

By default it uses output.swirl as input or output Siwrl file name 
but you can choose your own file name with "-f"

::

 clem@sirius:~/projects/FingerPrint$ ls -lh output.swirl
 -rw-rw-r-- 1 clem clem 2.4K Feb 20 15:51 output.swirl


To see the list of libraries your /bin/ls depends on along with
the local package name (this is what is stored in a swirl).
You can always use the verbose flag (-v) to create more output.

::

 clem@hermes:~/projects/FingerPrint$ fingerprint -dv
 File name:  output.swirl
 Swirl 2013-08-23 17:27
  ls.so.conf path list:
   /lib/i386-linux-gnu
   /usr/lib/i386-linux-gnu
   /usr/local/lib
   /lib/x86_64-linux-gnu
   /usr/lib/x86_64-linux-gnu
   /usr/lib/x86_64-linux-gnu/mesa
   /lib32
   /usr/lib32
  -- File List --
   /bin/ls  - coreutils 8.13-3ubuntu3.2 amd64
     Deps: librt.so.1, ld-linux-x86-64.so.2, libselinux.so.1, libacl.so.1, libc.so.6
     Provs: 
     /lib/x86_64-linux-gnu/ld-2.15.so  - libc6 2.15-0ubuntu10.4 amd64
     -> /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
       Deps: 
       Provs: ld-linux-x86-64.so.2
     /lib/x86_64-linux-gnu/libacl.so.1.1.0  - libacl1 2.2.51-5ubuntu1 amd64
     -> /lib/x86_64-linux-gnu/libacl.so.1
       Deps: libattr.so.1, libc.so.6
       Provs: libacl.so.1
     /lib/x86_64-linux-gnu/libc-2.15.so  - libc6 2.15-0ubuntu10.4 amd64
     -> /lib/x86_64-linux-gnu/libc.so.6
       Deps: ld-linux-x86-64.so.2
       Provs: libc.so.6
     /lib/x86_64-linux-gnu/librt-2.15.so  - libc6 2.15-0ubuntu10.4 amd64
     -> /lib/x86_64-linux-gnu/librt.so.1
       Deps: libpthread.so.0, libc.so.6
       Provs: librt.so.1
     /lib/x86_64-linux-gnu/libselinux.so.1  - libselinux1 2.1.0-4.1ubuntu1 amd64
       Deps: ld-linux-x86-64.so.2, libc.so.6, libdl.so.2
       Provs: libselinux.so.1
     /lib/x86_64-linux-gnu/libattr.so.1.1.0  - libattr1 1:2.4.46-5ubuntu1 amd64
     -> /lib/x86_64-linux-gnu/libattr.so.1
       Deps: libc.so.6
       Provs: libattr.so.1
     /lib/x86_64-linux-gnu/libpthread-2.15.so  - libc6 2.15-0ubuntu10.4 amd64
     -> /lib/x86_64-linux-gnu/libpthread.so.0
       Deps: ld-linux-x86-64.so.2, libc.so.6
       Provs: libpthread.so.0
     /lib/x86_64-linux-gnu/libdl-2.15.so  - libc6 2.15-0ubuntu10.4 amd64
     -> /lib/x86_64-linux-gnu/libdl.so.2
       Deps: ld-linux-x86-64.so.2, libc.so.6
       Provs: libdl.so.2


Scan the current system to verify compatibility with given swirl
i.e. all dependencies listed in the Swirl can be found:

::

 clem@sirius:~/projects/FingerPrint$ fingerprint -y


Verify that none of the dependencies have been modified
(it uses md5sum to check for changes).

::

 clem@sirius:~/projects/FingerPrint$ fingerprint -yi


You can query the swirl:

::

 clem@sirius:~/projects/FingerPrint$ fingerprint -q -S
 /lib/x86_64-linux-gnu/librt.so.1 && echo librt is used
 librt is used
 
 clem@sirius:~/projects/FingerPrint$ fingerprint -q -v -S
 /lib/x86_64-linux-gnu/libcrypt.so.1 || echo libcrypt is not used
 libcrypt is not used


Dynamic tracing
---------------
FingerPrint can dynamically trace a running process to properly detect dynamic
dependencies and opened files. To this extent it uses the POSIX ptrace system
call and it can trace spawned processes as well.

Dynamic tracing can trace dynamically loaded shared libraries and opened files.
If FingerPrint is compiled with stacktracer support (see Requirements for more info)
it can also detect which shared library initiated the open syscall. To dynamically
trace a program run Fingperprint with the '-c -x' flags:

::

 clem@hermes:~/projects/FingerPrint$ fingerprint -c -x xeyes
 Tracing terminated successfully
 File output.swirl saved


When displaying a Swirl created with the dynamic tracing it includes information
regarding open files and dynamically loaded libraries.

::

 clem@hermes:~/projects/FingerPrint$ fingerprint -d
 File name:  output.swirl
 Swirl 2013-08-23 17:43
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

It the example above you can see that the file ``/home/clem/.Xauthority`` was
pened by the ``/usr/lib/x86_64-linux-gnu/libXau.so.6.0.0`` shared library.

Authors and Contributors
------------------------
Fingerprint is an idea of Phil Papadopoulos and it is developed by Phil and Luca
Clementi.  This work is funded by NSF under the grant #1148473.


Support or Contact
------------------
If you are having trouble with FingerPrint or if you need some help you can post an
issue or contact me at clem \a\t sdsc dot edu.

