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


    def make_roll(self):
        """ """
        if not os.path.exists(self.archive_filename) :
            self.errors = "" + self.archive_filename + " does not exist"
            return False
        base_dir = self.archive_filename.split(".tar.gz")[0]
        # this is the list of package we will have to hadd
        self.packages = []
        # this is a list of swirlFile which will need to be installed
        # the additional self.files[0].source_path attribute has been added
        self.files = []

        # extract archive
        temp_workdir = tempfile.mkdtemp()
        self.tempbase_dir = os.path.join(temp_workdir, base_dir)
        archive_file = tarfile.open(self.archive_filename, 'r:gz')
        archive_file.extractall(temp_workdir)
        archive_file.close()

        # open swirl
        self.swirl = sergeant.readFromPickle(os.path.join(self.tempbase_dir, base_dir) \
                                        + ".swirl" ).swirl


        # for each swirl_file in exec
        # 1. check if swirl_file.package is present in the local yum repo
        #    if so add package it and stop
        # 2. check if for each dependency swirl_file can be found int the local yum repo
        # 2. check links
        # 3. copy files over with wrapper scripts

        # recursively resolve all depednencies of the execFile
        for swf in self.swirl.execedFiles:
            self.resolve_file(swf)

        #print self.packages
        for swf in self.files:
            print "including file ", swf.path, " source ", swf.source_path
        for pkg in self.packages:
            print "including pakcage ", pkg
        return True


    def resolve_file(self, swirl_file):
        """ this function recursively try to resolve the swirlFile"""
        # if swirl_file.path in yum db add rpm
        # else add swirl_file to self.files
        packages = []
        if 'ELF' in swirl_file.type and swirl_file.executable:
            # executable
            packages = self.get_package_from_dep([swirl_file.path])
            swirl_file.source_path = os.path.join(self.tempbase_dir, def_exec_dir,
                                                os.path.basename(swirl_file.path))
        elif 'ELF' in swirl_file.type and not swirl_file.executable:
            # library
            swirl_file.source_path = os.path.join(self.tempbase_dir, def_lib_dir,
                                                os.path.basename(swirl_file.path))
        elif any([ swirl_file.path.startswith(i) for i in sergeant.specialFolders ]):
            # this file belongs to the special folders let's skip it
            return
        else:
            #data
            packages = self.get_package_from_dep(swirl_file.path)
            swirl_file.source_path = os.path.join(self.tempbase_dir, def_data_dir,
                                                os.path.basename(swirl_file.path))
        if packages :
            if len(packages) > 1 :
                print "swirl_file ", swirl_file.path, " has two rpm ", packages
            # data files and executable files don't have provides so we need to check for them
            # in the yum DB using full path
            self.packages.append( packages[0] )
            return
        self.files.append(swirl_file)
        #
        # for each dep in swirlFile:
        dependency_dict = swirl_file.getDependenciesDict()
        for soname in dependency_dict:
        #    if soname solve with rpm add rpm and return
        #    if soname is already soved in self.files return
        #    else find swirlFile add it to self.files and call resolve_file
            if all([ self.get_swirl_file_by_prov(dep) for dep in dependency_dict[soname]]):
                #this soname is already resolved we can go to the next one
                continue
            else:
                #we need to resolve this dependency
                newSwirls = set([ self.swirl.getSwirlFileByProv(dep) for dep in dependency_dict[soname]])
                if len(newSwirls) != 1:
                    print "  --  nasty!!  --  ", swirl_file.path
                    for i in newSwirls:
                        print "    file ", i
                    return
                self.resolve_file(newSwirls.pop())


    def get_swirl_file_by_prov(self, dependency):
        """find the swirl file which provides the given dependency"""
        #TODO replicated code from swirl.py remove this!!
        for swF in self.files:
            if dependency in swF.provides :
                return swF
        return None


    def make_roll_devel(self):
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

    def get_package_from_dep(self, package_name):
        """ given a list of requires it return a list of packages name which can satisfy them
        and they are available in the currently enabled yum repository """
        import yum
        yb = yum.YumBase()
        matched = []
        for dep in package_name:
            matches = yb.searchPackageProvides( [dep] )
            if len(matches) > 0:
                matched += matches
            else:
                # we can't satisfy this dep so let's fail
                return []
        # I need to exclude the installed RPM from the return list
        return [pkg.name for pkg in yum.misc.unique(matched) if 'installed' not in pkg.repo.name ]


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


        def findWhoProvides(self, dependencies):
            """ """
            matches = yum.YumBase.searchPackageProvides(self, [str(depstring)])
