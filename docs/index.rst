.. Fingerprint documentation master file, created by
   sphinx-quickstart on Mon Feb  9 17:07:59 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Fingerprint
===========

FingerPrint is a software tool which can analyze arbitrary lists of binaries
and save all their dependencies information in a file (called Swirl) along
with other information.

A Swirl can then be used to understand if the given application can run on
another system or if some of the dependencies got modified since the
Swirl creation. Swirl can also be used to deploy the traced application
on a Rocks cluster.


Contents:

.. toctree::
   :maxdepth: 2

   userguide
   hacking 
   refs/modules


Authors and Contributors
------------------------
Fingerprint is an idea of Phil Papadopoulos and it is developed by Phil and Luca
Clementi. This work is funded by NSF under the grant #1148473.


Support or Contact
------------------
If you are having trouble with FingerPrint or if you need some help you can post an
email on the Rocks mailing list npaci-rocks-discussion@sdsc.edu or pust an issue on
github.

