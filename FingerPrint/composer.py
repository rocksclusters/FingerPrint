#!/usr/bin/python
#
# LC
#
# create archives an archive from a swirl and create rolls from an archive
# 
#

import os, string
import tempfile
import shutil
import tarfile

import sergeant

#
# compatibility with python2.4
#
if "any" not in dir(__builtins__):
    from FingerPrint.utils import any


def_exec_dir = "bin"
def_lib_dir = "lib"
def_data_dir = "data"


class Archiver:
    """It reads an already created swirl and:
      - it detects if it can run on this system
      - it detects what has been changed
      - print this swirl on the screen
    """


    def __init__(self, sergeant, archive_filename):
        """ """
        self.sergeant = sergeant
        self.archive_filename = archive_filename
        self.errors = None

    def archive(self):
        """        """
        #we need a valid swirl
        if not self.sergeant.check():
            self.errors = "The given fingerprint fails:\n  " + \
                '\n  '.join(self.sergeant.getError())
            return False
        # prepare the folders for the tar
        base_tar = tempfile.mkdtemp()
        base_dir = os.path.join(base_tar, self.archive_filename.split(".tar.gz")[0])
        exec_dir = os.path.join(base_dir, def_exec_dir)
        lib_dir = os.path.join(base_dir, def_lib_dir)
        data_dir = os.path.join(base_dir, def_data_dir)
        os.mkdir(base_dir)
        os.mkdir(exec_dir)
        os.mkdir(data_dir)
        os.mkdir(lib_dir)
        # copy all the files referenced by this swirl
        for swf in self.sergeant.swirl.swirlFiles:
            if 'ELF' in swf.type and swf.executable:
                temp_path = exec_dir
            elif 'ELF' in swf.type and not swf.executable:
                temp_path = lib_dir
            elif swf.path[0] == '$' or \
                any([ swf.path.startswith(i) for i in sergeant.specialFolders ]):
                #TODO maybe we could keep user data into a special folder?
                # this file belongs to the special folders let's skip it
                continue
            else:
                temp_path = data_dir
            if not os.path.exists(os.path.join(temp_path, os.path.basename(swf.path))) and \
                os.path.exists(swf.path):
                # do not copy twice the same file
                shutil.copy2(swf.path, temp_path)
            for i in swf.links:
                new_link = os.path.join(temp_path, os.path.basename(i))
                if not os.path.exists( new_link ):
                    os.symlink( os.path.basename(swf.path), new_link)
        # copy the swirl itself
        shutil.copy2(self.sergeant.filename, base_dir)
        # let's do the tar
        tar = tarfile.open(self.archive_filename, "w:gz")
        cwd = os.getcwd()
        os.chdir(base_tar)
        tar.add(".")
        tar.close()
        os.chdir(cwd)
        shutil.rmtree(base_tar)
        return True



    def getError(self):
        """        """
        return self.errors


class Roller:
    """ this class make a roll out of an fingerprint archive"""

    def __init__(self, archive_filename, roll_name):
        """ """
        self.archive_filename = archive_filename
        self.roll_name = roll_name
        self.errors = None



    def makeRoll(self):
        """ rocks create package /root/methanol/test/ testpackage prefix=/"""
        if not os.path.exists(self.archive_filename) :
            self.errors = "" + self.archive_filename + " does not exist"
            return False
        base_dir = self.archive_filename.split(".tar.gz")[0]

        ## make the output directory
        #destination_base_dir = "/opt"
        #dest_dir = os.path.join(destination_base_dir, base_dir)
        #if os.path.exists(dest_dir) :
        #    self.errors = "Destiation dir " + dest_dir + " already exists. Please remove it."
        #    return False
        #os.mkdir(dest_dir)
        #virtual_root = os.path.join(dest_dir, 'cde-root')

        # extract archive
        temp_workdir = tempfile.mkdtemp()
        tempbase_dir = os.path.join(temp_workdir, base_dir)
        archive_file = tarfile.open(self.archive_filename, 'r:gz')
        archive_file.extractall(temp_workdir)
        archive_file.close()

        # open swirl
        serg = sergeant.readFromPickle(os.path.join(tempbase_dir, base_dir) \
                                        + ".swirl" )

        # 1. check package
        # 2. check links
        # 3. copy files over with wrapper scripts

        outfiles = open("out_files.sh", 'w')
        # copy all the files referenced by this swirl
        for swf in serg.swirl.swirlFiles:
            if 'ELF' in swf.type and swf.executable:
                # its executable let's just place it where it belongs
                source_path = os.path.join(tempbase_dir, def_exec_dir, os.path.basename(swf.path))
            elif 'ELF' in swf.type and not swf.executable:
                source_path = os.path.join(tempbase_dir, def_lib_dir, os.path.basename(swf.path))
            elif any([ swf.path.startswith(i) for i in sergeant.specialFolders ]):
                # this file belongs to the special folders let's skip it
                continue
            else:
                source_path = os.path.join(tempbase_dir, def_data_dir, os.path.basename(swf.path))

            #dest_path = wirtual_root + swf.path
            dest_path = swf.path
            if os.path.exists(dest_path) :
                print "file ", dest_path, " is already present on the system"
                continue
            if not os.path.exists(source_path) :
                print "file ", source_path, " is not present in the archive"
                continue
            if not os.path.exists( os.path.dirname(dest_path) ) :
                os.makedirs( os.path.dirname(dest_path) )
            shutil.copy2(source_path, dest_path)
            outfiles.write("rm -fr " + dest_path + '\n')
            for i in swf.links:
                if os.path.exists(i) :
                    print "skipping link ", i
                    continue
                print "making a link ", i
                os.symlink( dest_path, i)
                outfiles.write("rm -fr " + i + '\n')
        outfiles.close()
        return True


    def getError(self):
        """        """
        return self.errors


    def useRPMPackage(self, package_name):
        """ return true if the package_name is available in the current yum database
        and package_name is the same version as the one available in the local yum DB
        """
        #this whole thing will run only on REDHAT system
        import yum
        #remove versioning from the name
        s = package_name
        #remove arch
        i = s.rsplit(".", 1)
        if len(i) > 0 :
                arch = i[1]
        else:
                arch = ""
        s = i[0]
        #remove rpm version
        i = s.rsplit("-", 1)
        if len(i) > 0 :
                rpm_ver = i[1]
        else:
                rpm_ver = ""
        s = i[0]
        #remove software version
        i = s.rsplit("-", 1)
        if len(i) > 0 :
                soft_ver = i[1]
        else:
                sorf_ver = ""
        package_short_name = i[0]
        # force arch while searching for packages
        package_short_name += "." + arch
        yb = yum.YumBase()
        pl = yb.doPackageLists('all')
        exactmatch, matched, unmatched = yum.packages.parsePackages(pl.available + pl.installed, ["list", package_short_name])
        #exactmatch = yum.misc.unique(exactmatch)
        #for i in exactmatch:
        #    print "p: ", i
        if len(exactmatch) > 0 :
            big_pkg = exactmatch[0]
            for pkg in exactmatch:
                if pkg.verGT(big_pkg):
                    big_pkg = pkg
        if str(big_pkg) == package_name:
            return True
        else:
            return False
