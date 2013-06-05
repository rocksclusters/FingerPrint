#!/usr/bin/python
#
# LC
#
# create archives an archive from a swirl and create rolls from an archive
# 
#

import os, string, stat, logging
import tempfile
import shutil
import tarfile

import sergeant, utils

#
# compatibility with python2.4
#
if "any" not in dir(__builtins__):
    from FingerPrint.utils import any


def_exec_dir = "bin"
def_lib_dir = "lib"
def_data_dir = "data"
logger = logging.getLogger('fingerprint')


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

    def archive(self):
        """        """
        #we need a valid swirl
        if not self.sergeant.check():
            logger.error("The fingerprint " + self.sergeant.filename + " fails:\n  " +
                "\n  ".join(self.sergeant.getError()) + "\n\nThe archive creation failed.\n")
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
                if sergeant.prelink :
                    utils.getOutputAsList([sergeant.prelink, "-u",
                        os.path.join(temp_path, os.path.basename(swf.path))])
            #for i in swf.links:
            #    new_link = os.path.join(temp_path, os.path.basename(i))
            #    if not os.path.exists( new_link ):
            #        os.symlink( os.path.basename(swf.path), new_link)
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


class Roller:
    """ this class make a roll out of an fingerprint archive"""

    # this is a list of rpm packages which are broken or known to cause problem
    excluded_packages = ["fftw"] # fftw rocks rpm is compiled only statically

    def __init__(self, archive_filename, roll_name):
        """ """
        self.archive_filename = archive_filename
        self.roll_name = roll_name
        import yum
        self.yb = yum.YumBase()


    def make_roll(self):
        """ """
        if not os.path.exists(self.archive_filename) :
            logger.error("The file " + self.archive_filename + " does not exist" +
                " (specify a different one with -f option)")
            return False
        base_dir = self.archive_filename.split(".tar.gz")[0]
        # this is the list of package we will have to hadd
        self.packages = set()
        self.skipped_swfs = set()
        # this is a list of swirlFile which will need to be installed
        # the additional self.files[0].source_path attribute has been added
        self.files = []
        # internal swirl package we want to include in the final rpm
        self.wanted_pcks = set()
        # list of rpm pakcage we have to exclude
        self.disable_pcks = set()


        #
        # read the content of the archive
        #
        temp_workdir = tempfile.mkdtemp()
        self.tempbase_dir = os.path.join(temp_workdir, base_dir)
        archive_file = tarfile.open(self.archive_filename, 'r:gz')
        archive_file.extractall(temp_workdir)
        archive_file.close()

        # open swirl
        self.swirl = sergeant.readFromPickle(os.path.join(self.tempbase_dir, base_dir) \
                                        + ".swirl" ).swirl

        #
        # recursively resolve all dependencies of the execedFile
        #
        for swf in self.swirl.execedFiles:
            self.resolve_file(swf)

        if self.files:
            #
            # make an rpm with all the files
            #
            rpm_tmp_dir = tempfile.mkdtemp()
            # laydown the file
            for swf in self.files:
                dest_path = rpm_tmp_dir + swf.path
                if not os.path.exists(swf.source_path) :
                    logger.debug("File " + swf.source_path + " is not present in the archive")
                    continue
                if not os.path.exists( os.path.dirname(dest_path) ):
                    os.makedirs( os.path.dirname(dest_path) )
                if 'ELF' in swf.type and swf.executable:
                    # we need a wrapper script to set the env
                    shutil.copy2(swf.source_path, dest_path + ".orig")
                    f=open(dest_path, 'w')
                    f.write("#!/bin/bash\n\n")
                    ldconf_written = False
                    for i in swf.env:
                        if self.swirl.ldconf_paths and i.startswith('LD_LIBRARY_PATH'):
                            #we need to prepend the ldconf_paths
                            prefix = 'LD_LIBRARY_PATH=' + ':'.join( self.swirl.ldconf_paths )
                            ldconf_written = True
                            if i.split('=')[1] :
                                prefix += ':' + i.split('=')[1]
                            i = prefix
                        f.write("export " + i + ":$" + i.split("=")[0] + "\n")
                    if not ldconf_written:
                        f.write("export LD_LIBRARY_PATH=" +
                                ':'.join( self.swirl.ldconf_paths ) + ':$LD_LIBRARY_PATH\n')
                    f.write("\n")
                    f.write(swf.path + ".orig $@\n")
                    f.close()
                    os.chmod(dest_path, 0755)
                else:
                    shutil.copy2(swf.source_path, dest_path)
                # and the symlinks
                for i in swf.links:
                    dest_link = rpm_tmp_dir + i
                    # source link must be without the rpm_tmp_dir part
                    if not os.path.isdir(os.path.dirname(dest_link)):
                        os.makedirs(os.path.dirname(dest_link))
                    os.symlink( swf.path, dest_link)
            # rocks create package "/tmp/tmpAFDASDF/*" pakcagename prefix=/
            logger.info("RPM root dir " + rpm_tmp_dir)
            (output, retcode) = utils.getOutputAsList( ["rocks", "create",
                        "package", rpm_tmp_dir + "/*", base_dir, "prefix=/"])
            if any([i for i in output if 'RPM build errors' in i ]):
                logger.error('\n'.join(output))
                logger.error("Error building base RPM package\n")
                return False
            logger.info('\n'.join(output))
            #TODO need to run ldconfig
            self.packages.add(base_dir)
        else:
            logger.info("No files to include in the custom RPM")

        print "yum install ", ' '.join(self.packages)
        print "yum remove ", ' '.join(self.disable_pcks)
        print "Skipped swirl Files:\n", '\n'.join([i.path for i in self.skipped_swfs])
        return True


    def resolve_file(self, swirl_file):
        """ this function recursively try to resolve the swirlFile

        this function will add the package name to self.packages if it can find
        an rpm which can sattisfy it, if not, it will add this swirlf_file to the
        self.files """
        if swirl_file in self.files:
            return
        # if swirl_file.path in yum db add rpm to self.packages
        # else add swirl_file to self.files
        packages = []
        if 'ELF' in swirl_file.type and swirl_file.executable:
            # executable
            packages = self.get_package_from_dep([swirl_file.path])
            swirl_file.source_path = os.path.join(self.tempbase_dir, def_exec_dir,
                                                os.path.basename(swirl_file.path))
        elif 'ELF' in swirl_file.type and not swirl_file.executable:
            # library
            packages = self.get_package_from_dep(swirl_file.getPaths(), False)
            swirl_file.source_path = os.path.join(self.tempbase_dir, def_lib_dir,
                                                os.path.basename(swirl_file.path))
        elif swirl_file.path[0] == '$' or \
            any([ swirl_file.path.startswith(i) for i in sergeant.specialFolders ]):
            # this file belongs to the special folders or it's a relative path
            return
        else:
            #data
            packages = self.get_package_from_dep([swirl_file.path])
            swirl_file.source_path = os.path.join(self.tempbase_dir, def_data_dir,
                                                os.path.basename(swirl_file.path))
        if packages :
            if len(packages) > 1 :
                #TODO remove print statment
                error_message = "The Swirl file " + swirl_file.path + " "
                error_message += "resoves with more than one RPMs: " + ", ".join(packages)
                logger.error(error_message)
                raise Exception(error_message)
            if swirl_file.package not in self.wanted_pcks and \
                packages[0] not in self.excluded_packages:
                self.skipped_swfs.add( swirl_file  )
                self.packages.add( packages[0] )
                # so we found a package which can handle this swf but we should still process its
                # opened file in case it is an interpreter
                self._process_open_file(swirl_file)
                logger.debug("Adding package " + packages[0] + " for swirl " + swirl_file.path)
                return
            else:
                self.disable_pcks |= set(packages)
        logger.debug("Adding swirl: " + swirl_file.path)
        if 'ELF' in swirl_file.type :
            # for ELF swf if we select the libmpi.so.2 we also want to carry all its dynamic libraries
            # even if their name matches an available package for this reason we use wanted_pcks
            self.wanted_pcks.add(swirl_file.package)
        self.files.append(swirl_file)
        #
        # for each swf in swirlFile.all_dependencies
        #   if not already in self.files resolve_file(swf)
        deps = self.swirl.getListSwirlFileProvide( swirl_file.staticDependencies )+\
                                swirl_file.dynamicDependencies
        for new_swf in deps:
            if new_swf not in self.files:
                #this file is already in the included files
                self.resolve_file(new_swf)
        self._process_open_file(swirl_file)


    def _process_open_file(self, swirl_file):
        """ scan the open files of this swirl """
        for exec_file in swirl_file.openedFiles:
            for open_file in swirl_file.openedFiles[exec_file]:
                if open_file not in self.files:
                    self.resolve_file(open_file)



    def get_swirl_file_by_prov(self, dependency):
        """find the swirl file which provides the given dependency"""
        #TODO replicated code from swirl.py remove this!!
        for swF in self.files:
            if dependency in swF.provides :
                return swF
        return None


    def get_package_from_dep(self, package_name, match_all = True):
        """ given a list of requires it return a list of packages name which can satisfy them
        and they are available in the currently enabled yum repository """
        import yum
        excludeRPMs = ["foundation-", "rocks-ekv", "condor"]
        matched = []
        for dep in package_name:
            if '(GLIBC_PRIVATE)' in dep:
                # glibc_private is not tracked in the rpm database so skip it
                continue
            matches = self.yb.searchPackageProvides( [dep] )
            if len(matches) > 0:
                for rpm in matches:
                    if all([ i not in rpm.name for i in excludeRPMs ]):
                        matched.append(rpm)
            elif match_all:
                # we can't satisfy this dep so let's fail
                return []
            else:
                pass
        # do I need to exclude the installed RPM from the return list?
        # if 'installed' not in pkg.repo.name ]
        return list(set([pkg.name for pkg in yum.misc.unique(matched)]))


    def useRPMPackage(self, package_name):
        """ return true if the package_name is available in the current yum database
        and package_name is the same version as the one available in the local yum DB

        TODO unused at the moment
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
