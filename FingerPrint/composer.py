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
import platform, glob

import sergeant, utils

#
# compatibility with python2.4
#
if "any" not in dir(__builtins__):
    from FingerPrint.utils import any


def_base_dir = "output"
def_exec_dir = os.path.join(def_base_dir, "bin")
def_lib_dir = os.path.join(def_base_dir, "lib")
def_data_dir = os.path.join(def_base_dir, "data")
def_swirl_path = os.path.join(def_base_dir, "output.swirl")

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
        base_path = os.path.join(base_tar, def_base_dir)
        os.mkdir(base_path)
        # copy all the files referenced by this swirl
        for swf in self.sergeant.swirl.swirlFiles:
            if swf.path[0] == '$' or sergeant.is_special_folder(swf.path):
                #TODO maybe we could keep user data into a special folder?
                # this file belongs to the special folders let's skip it
                continue
            dest_path_dir = os.path.join(base_path, swf.md5sum)
            dest_path_full = os.path.join(dest_path_dir, os.path.basename(swf.path))
            if not os.path.exists(dest_path_full) and \
                os.path.exists(swf.path):
                # do not copy twice the same file
                os.mkdir(dest_path_dir)
                shutil.copy2(swf.path, dest_path_dir)
                if sergeant.prelink :
                    utils.getOutputAsList([sergeant.prelink, "-u", dest_path_full])
            #for i in swf.links:
            #    new_link = os.path.join(temp_path, os.path.basename(i))
            #    if not os.path.exists( new_link ):
            #        os.symlink( os.path.basename(swf.path), new_link)
        # copy the swirl itself
        shutil.copy2(self.sergeant.filename, os.path.join(base_tar, def_swirl_path))
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
    #TODO unify this with the excludeRPMs in the get_package_from_dep
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
        self.users = set()

        #
        #    ----------------      read the content of the archive
        #
        temp_workdir = tempfile.mkdtemp()
        logger.info("Extracting archive in %s..." % temp_workdir)
        tar_tmp_dir = os.path.join(temp_workdir, def_base_dir)
        archive_file = tarfile.open(self.archive_filename, 'r:gz')
        archive_file.extractall(temp_workdir)
        archive_file.close()
        # open swirl
        logger.info("Reading swirl %s" % os.path.join(temp_workdir, def_swirl_path))
        self.swirl = sergeant.readFromPickle(os.path.join(temp_workdir,
                        def_swirl_path)).swirl

        #
        #    ----------------      recursively resolve all dependencies of the execedFile
        #
        for swf in self.swirl.execedFiles:
            self.resolve_file(swf)
        logger.debug("Dependency resolution terminated. Skipped swirl Files:\n - " +
                                '\n - '.join([i.path for i in self.skipped_swfs]))
        #
        #    ----------------      make rpms with all the files
        #
        rpm_tmp_dir = tempfile.mkdtemp()
        home_rpm_tmp_dir = tempfile.mkdtemp()
        rpm_list = set()
        # laydown the file
        for swf in self.files:
            if swf.path.startswith("/home/"):
                # files in /home need special treatment 1. we need to create a user
                # 2 they need to go in /export/home only on the Frontend
                rpm_list.add((home_rpm_tmp_dir,self.roll_name + "-home"))
                tmp_user = swf.path.split("/home/",1)[1]
                self.users.add(tmp_user.split("/",1)[0])
                dest_path = home_rpm_tmp_dir + "/export" + swf.path
            else:
                rpm_list.add((rpm_tmp_dir,self.roll_name))
                dest_path = rpm_tmp_dir + swf.path
            source_path = os.path.join(tar_tmp_dir, swf.md5sum,
                            os.path.basename(swf.path))
            if not os.path.exists(source_path) :
                logger.debug("File " + source_path + " is not present in the archive")
                continue
            if not os.path.exists( os.path.dirname(dest_path) ):
                os.makedirs( os.path.dirname(dest_path) )
            if 'ELF' in swf.type and swf.executable:
                # we need a wrapper script to set the environment
                shutil.copy2(source_path, dest_path + ".orig")
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
                shutil.copy2(source_path, dest_path)
            # and the symlinks
            for i in swf.links:
                dest_link = rpm_tmp_dir + i
                # source link must be without the rpm_tmp_dir part
                if not os.path.isdir(os.path.dirname(dest_link)):
                    os.makedirs(os.path.dirname(dest_link))
                os.symlink( swf.path, dest_link)
        # files are in place so let's make the RPMs
        for (base_dir, rpm_name) in rpm_list:
            if self.make_rpm(base_dir, rpm_name):
                if '-home-' not in rpm_name:
                    self.packages.add(rpm_name)
            else:
                return False
        shutil.rmtree(temp_workdir)
        #
        #    ----------------      create roll copy files there and build
        #
        logger.info("Creating roll " + self.roll_name)
        (output, retcode) = utils.getOutputAsList( ["rocks", "create",
                "new", "roll", self.roll_name] )
        if retcode :
            logger.error("Unable to create the roll")
            if os.path.exists(self.roll_name):
                logger.error("Remove the direcotry: rm -rf %s" % (self.roll_name))
            logger.error(" > " + "\n > ".join(output))
            return False
        shutil.rmtree(self.roll_name + "/src/" + self.roll_name)
        shutil.rmtree(self.roll_name + "/src/usersguide")
        os.remove(self.roll_name + "/nodes/" + self.roll_name + ".xml")
        dest = self.roll_name + "/RPMS/" + platform.machine()
        os.makedirs(dest)
        # copying global RPM
        source = glob.glob(self.roll_name + "-1.0-*.rpm")
        if len(source) == 1:
            logger.info("Coping RPM in: " + dest + "/" + source[0])
            shutil.copy2(source[0], dest)
            # create the base-nodea.xml
            node_base_xml = self.node_base_xml_top
            #   1. install packages
            for package in self.packages:
                node_base_xml += '<package>' + package + '</package>\n'
            #   2. remove pakcages
            for package in self.disable_pcks:
                node_base_xml += '<package>-' + package + '</package>\n'
            #   3. set the paths
            new_paths = set()
            for swf in self.swirl.execedFiles:
                new_paths |= set([os.path.dirname(i) for i in swf.getPaths()])
            node_base_xml += self.node_base_xml_bottom % (self.roll_name, ' '.join(new_paths))
            self.write_file(self.roll_name + "/nodes/" + self.roll_name + "-base.xml",
                    node_base_xml)
        # copying -home- RPM
        source = glob.glob(self.roll_name + "-home-1.0-*.rpm")
        if len(source) == 1:
            logger.info("Coping RPM in: " + dest + "/" + source[0])
            shutil.copy2(source[0], dest)
            # create the server-node
            self.write_file(self.roll_name + "/nodes/" + self.roll_name + "-server.xml",
                    self.node_server_xml % (self.roll_name, ' '.join(self.users)))
        # create the graph xml
        self.write_file(self.roll_name + "/graphs/default/" + self.roll_name + ".xml",
                self.graph_node_xml % (self.roll_name, self.roll_name, self.roll_name))
        # make the roll
        os.chdir(self.roll_name)
        (output, retcode) = utils.getOutputAsList(["make", "roll"])
        os.chdir("..")
        roll_path = glob.glob(self.roll_name + "/" + self.roll_name + "*.iso")
        if retcode or len(roll_path) < 1:
            # error :-(
            logger.error("Unable to make the roll")
            logger.error(' > ' + '\n > '.join(output))
            return False
        logger.error("Roll %s succesfully created.\nTo add it to your distribution:" % roll_path[0])
        logger.error("rocks add roll " + roll_path[0])
        logger.error("rocks enable roll " + self.roll_name)
        logger.error("cd /export/rocks/install")
        logger.error("rocks create distro")
        logger.error("rocks run roll " + self.roll_name + " | bash")
        return True

    def write_file(self, file_name, string):
        """write string into file_name and log it"""
        logger.info("Writing file: " + file_name)
        logger.debug(" > " + "\n > ".join(string.split("\n")))
        f = open(file_name, 'w')
        f.write(string)
        f.close()


    def make_rpm(self, base_path, rpm_name):
        """ makes an rpm called rpm_name starting from base_path

        return False if something went wrong
        """
        # rocks create package "/tmp/tmpAFDASDF/*" pakcagename prefix=/
        logger.info("RPM " + rpm_name + " root dir " + base_path)
        (output, retcode) = utils.getOutputAsList( ["rocks", "create",
                    "package", base_path + "/*", rpm_name, "prefix=/"])
        if any([i for i in output if 'RPM build errors' in i ]):
            logger.error(' > ' + '\n > '.join(output))
            logger.error("Error building " + rpm_name + " RPM package\n")
            return False
        logger.debug(' > '+ '\n > '.join(output))
        shutil.rmtree(base_path)
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
        elif 'ELF' in swirl_file.type and not swirl_file.executable:
            # library
            packages = self.get_package_from_dep(swirl_file.getPaths(), False)
        elif swirl_file.path[0] == '$' or sergeant.is_special_folder(swirl_file.path):
            # this file belongs to the special folders or it's a relative path
            return
        else:
            #data
            packages = self.get_package_from_dep([swirl_file.path])
        if packages :
            if len(packages) > 1 :
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

    graph_node_xml = '''<?xml version="1.0" standalone="no"?>
<graph>
<description>
The FingerPrint Roll
</description>
<edge from="client">
<to>%s-base</to>
</edge>
<edge from="server">
<to>%s-server</to>
<to>%s-base</to>
</edge>
</graph>'''

    node_server_xml = '''<?xml version="1.0" standalone="no"?>
<kickstart>
<description>
FingerPrint roll
</description>
<package>%s-home</package>
<post>
users="%s"
for i in $users; do
    /usr/sbin/useradd -m $i
    #skel was not copied by useradd so we need to do it manually
    /bin/cp -r /etc/skel/.[a-zA-Z0-9]* /export/home/$i/
    /bin/chown -R $i:$i /export/home/$i
done
</post>
</kickstart>'''

    node_base_xml_top = '''<?xml version="1.0" standalone="no"?>
<kickstart>
<description>
FingerPrint
</description>
'''
    node_base_xml_bottom = '''
<post>
<file name="/etc/profile.d/%s-paths.sh" perms="0755">
#!/bin/bash
dirs="%s"
for dir in $dirs; do
  if [ -d ${dir} ]; then
    if ! echo ${PATH} | /bin/grep -q ${dir} ; then
      export PATH=${dir}:${PATH}
    fi
  fi
done
</file>
</post>
</kickstart>
'''
