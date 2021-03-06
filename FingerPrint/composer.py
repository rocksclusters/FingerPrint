#!/usr/bin/python
#
# LC
#
# creates a swirl archive from a swirl file 
# creates a roll from a swirl archive
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


# let's skip vairous private files which should not be archived
specialFile = ["id_rsa", "id_rsa.pub", "id_dsa", "id_dsa.pub", "known_hosts", ".Xauthority"]

def is_special_file(path):
    """
    :type path: string
    :param path: a path to a file

    :rtype: bool
    :return: it returns true if the path points to a file which contains
             personal data
    """
    return any([ path.endswith(i) for i in specialFile ])



class Archiver:
    """
    Given an already created swirl it creates a Swirl archive

    :type sergeant: :class:`FingerPrint.sergeant.Sergeant`
    :param sergeant: An instance of sergenat class pointing to the swirl 
        we want to archive

    :type archive_filename: string
    :param archive_filename: string containing the output file name for the archive
    """


    def __init__(self, sergeant, archive_filename):
        """
        Default constructor
	"""
        self.sergeant = sergeant
        self.archive_filename = archive_filename

    def archive(self):
        """
        It triggers the creation of the archive.

        :rtype: bool
        :return: it returns false in case of failure
        """
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
            if swf.path[0] == '$' or sergeant.is_special_folder(swf.path) or \
                            is_special_file(swf.path):
                #TODO maybe we could keep user data into a special folder?
                # this file belongs to the special folders let's skip it
                continue
            if os.path.exists(swf.path) and swf.md5sum:
		# the file was not a temporary file
                dest_path_dir = os.path.join(base_path, swf.md5sum)
                dest_path_full = os.path.join(dest_path_dir, os.path.basename(swf.path))
                if not os.path.exists(dest_path_full):
                    # do not copy twice the same file
                    if not os.path.exists(dest_path_dir):
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
    """ 
    this class make a roll out of an fingerprint archive

    :type archive_filename: string
    :param archive_filename: a path to the Swirl Archive file

    :type roll_name: string
    :param roll_name: the name of the roll that we want to create
    """

    # this is a list of rpm packages which are broken or known to cause problem
    #TODO unify this with the excludeRPMs in the _get_package_from_dep
    _excluded_packages = ["fftw"] # fftw rocks rpm is compiled only statically

    # these varaibles will be merged (prepended) with the local variable values
    # in the wrapper script
    _append_variables = ['PATH', 'LD_LIBRARY_PATH', 'LD_PRELOAD']
    # where all the remapped file will be placed
    _remapper_base_path = "/opt/rocks/remapper/"
    _remapper_executable = "/opt/rocks/bin/remapper"

    def __init__(self, archive_filename, roll_name):
        """ """
        self.archive_filename = archive_filename
        self.roll_name = roll_name
        import yum
        self.yb = yum.YumBase()


    def make_roll(self, fingerprint_base_path, use_remapping = False):
        """
        It creates a roll from a swirl archive.


        :type fingerprint_base_path: string
        :param fingerprint_base_path: a string pointing to the base path of the
                                      fingerprint source code. Used to find the
                                      remapper source code
        :type use_remapping: bool
        :param use_remapping: if True it will use the remapper technology when 
                              creating the roll

        :rtype: bool
        :return: it returns false in case of failure
        """
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
        # keeps track of already processed package in self._resolve_file()
        # so we do not process a package twice
        self.processed_package = []
        # internal swirl package we want to include in the final rpm
        self.wanted_pcks = set()
        # list of rpm pakcage we have to exclude
        self.disable_pcks = set()

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
            self._resolve_file(swf, use_remapping)
        logger.debug("Dependency resolution terminated. Skipped swirl Files:\n - " +
                                '\n - '.join([i.path for i in self.skipped_swfs]))
        #
        #    ----------------      make rpms with all the files
        #
        # list of user that should be added
        self.users = set()
        rpm_tmp_dir = tempfile.mkdtemp()
        home_rpm_tmp_dir = tempfile.mkdtemp()
        rpm_list = set()
        remapper_rpm_tmp_dir = rpm_tmp_dir + self._remapper_base_path
        # laydown the file
        for swf in self.files:
            source_path = os.path.join(tar_tmp_dir, str(swf.md5sum),
                            os.path.basename(swf.path))
            if not os.path.exists(source_path) :
		# if the file is not in the archive do not go on
                logger.debug("File " + source_path + " is not present in the archive")
                continue
            # if use_remapping = true swf must be executable 
            # if use_remapping = false just follow the first swf.path.startswith("/home/")
            if swf.path.startswith("/home/"):
                # files in /home need special treatment 1. we need to create a user
                # 2 they need to go in /export/home only on the Frontend
                rpm_list.add((home_rpm_tmp_dir,self.roll_name + "-home"))
                tmp_user = swf.path.split("/home/",1)[1]
                self.users.add(tmp_user.split("/",1)[0])
                rpm_prefix_dir = home_rpm_tmp_dir + "/export"
            else:
                rpm_list.add((rpm_tmp_dir,self.roll_name))
                rpm_prefix_dir = rpm_tmp_dir
            dest_path = rpm_prefix_dir + swf.path
            if not os.path.exists( os.path.dirname(dest_path) ):
                os.makedirs( os.path.dirname(dest_path) )
            if getattr(swf, 'executable', False):
                # we need a wrapper script to set the environment
                shutil.copy2(source_path, dest_path + ".orig")
                f=open(dest_path, 'w')
                f.write("#!/bin/bash\n\n")
                ldconf_written = False
                env = None
                if 'ELF' not in swf.type:
                    # this is not a ELF but is a script so we need to get the
                    # env from its parent swirl file (the interpreter)
                    for execswf in self.swirl.execedFiles:
                        if swf in execswf.openedFiles[execswf.path]:
                            env = execswf.env
                            break
                else:
                    env = swf.env
                if env == None:
                    logger.error('Unable to find interpreter for ', swf)
                    logger.error('Failing on ', swf)
                    return False
                for env_variable in env:
                    if '=' not in env_variable:
                        continue
                    if env_variable.startswith('HYDI'):
                        # MVAPICH 2.x HYDI_CONTROL_FD is used be hydra_proxy_mpi to comunicate
                        # subprocesses the control socket
                        continue
                    variable_name = env_variable.split('=')[0]
                    variable_value = env_variable.split('=')[1]
                    if any([ env_variable.startswith(i) for i in self._append_variables]):
                        # for these variables we want to add their content to
                        # the corresponding system variable values
                        if self.swirl.ldconf_paths and env_variable.startswith('LD_LIBRARY_PATH'):
                            variable_value = variable_value + ':' + ':'.join(self.swirl.ldconf_paths)
                            ldconf_written = True
                        f.write("export " + variable_name + "=\"" + variable_value + ":$" +
                            variable_name + "\"\n")
                    else:
                        # for all the other variables we simply want to define them
                        # if they are not already defined them
                        f.write("if [ -z \"$" + variable_name + "\" ]; then export " +
                            variable_name + "=\"" + variable_value + "\"; fi\n")
                if not ldconf_written and self.swirl.ldconf_paths:
                    f.write("export LD_LIBRARY_PATH=\"" +
                            ':'.join( self.swirl.ldconf_paths ) + ':$LD_LIBRARY_PATH\"\n')
                f.write("\n")
                if use_remapping and 'ELF' in swf.type:
                    f.write(self._remapper_executable + " ")
                    loader = self.swirl.getLoader(swf)
                    if loader:
                        f.write(self._remapper_base_path +\
					loader.path + " ")
                f.write(swf.path + ".orig $@\n")
                f.close()
                os.chmod(dest_path, 0755)
            else:
                if use_remapping:
                    tmp_path = remapper_rpm_tmp_dir + os.path.dirname(swf.path)
                    if not os.path.exists(tmp_path):
                        os.makedirs(tmp_path)
                    shutil.copy2(source_path, tmp_path + '/' + os.path.basename(swf.path))
                else:
                    shutil.copy2(source_path, dest_path)
            # if use remapping we don't need the symlinks
            if use_remapping and not getattr(swf, 'executable', False):
                continue
            # and the symlinks
            for i in swf.links:
                dest_link = rpm_prefix_dir + i
                # source link must be without the rpm_tmp_dir part
                if not os.path.isdir(os.path.dirname(dest_link)):
                    os.makedirs(os.path.dirname(dest_link))
                os.symlink( swf.path, dest_link)
        #
        #    ----------------      create file mapping and include remapper in the RPM
        #
        if use_remapping :
            if not os.path.exists(rpm_tmp_dir + "/etc"):
                os.mkdir(rpm_tmp_dir + "/etc")
            make_mapping_file(self.files, rpm_tmp_dir + "/etc/fp_mapping",
                    self._remapper_base_path)
            build_remapper_path = fingerprint_base_path + '/remapper'
            (output, retcode) = utils.getOutputAsList( ["make", "-C",
                    build_remapper_path] )
            if retcode :
                logger.error("Unable to built remapper")
                logger.error("You need to install make and gcc")
                logger.error(" > " + "\n > ".join(output))
                return False
            logger.debug(' > '+ '\n > '.join(output))
            remapper_basedir = rpm_tmp_dir + os.path.dirname(self._remapper_executable)
            if not os.path.exists(remapper_basedir):
                os.makedirs(remapper_basedir)
            shutil.copy2(build_remapper_path + "/remapper", remapper_basedir)
            #let's notify we have to build the base RPM
            rpm_list.add((rpm_tmp_dir,self.roll_name))
        #
        #    ----------------      files are in place so let's make the RPMs
        #
        for (base_dir, rpm_name) in rpm_list:
            if self._make_rpm(base_dir, rpm_name):
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
            node_base_xml = self._node_base_xml_top
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
            node_base_xml += self._node_base_xml_bottom % (self.roll_name, ' '.join(new_paths))
            self._write_file(self.roll_name + "/nodes/" + self.roll_name + "-base.xml",
                    node_base_xml)
        # copying -home- RPM
        source = glob.glob(self.roll_name + "-home-1.0-*.rpm")
        if len(source) == 1:
            logger.info("Coping RPM in: " + dest + "/" + source[0])
            shutil.copy2(source[0], dest)
            # create the server-node
            self._write_file(self.roll_name + "/nodes/" + self.roll_name + "-server.xml",
                    self._node_server_xml % (self.roll_name, ' '.join(self.users)))
        # create the graph xml
        self._write_file(self.roll_name + "/graphs/default/" + self.roll_name + ".xml",
                self._graph_node_xml % (self.roll_name, self.roll_name, self.roll_name))
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

    def _write_file(self, file_name, string):
        """write string into file_name and log it"""
        logger.info("Writing file: " + file_name)
        logger.debug(" > " + "\n > ".join(string.split("\n")))
        f = open(file_name, 'w')
        f.write(string)
        f.close()


    def _make_rpm(self, base_path, rpm_name):
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


    def _resolve_file(self, swirl_file, use_remapping = False):
        """ this function recursively try to resolve the swirlFile

        this function will add the package name to self.packages if it can find
        an rpm which can sattisfy it, if not, it will add this swirlf_file to the
        self.files """
        if swirl_file in self.files or swirl_file in self.processed_package:
            return
        self.processed_package.append(swirl_file)
        # if swirl_file.path in yum db add rpm to self.packages
        # else add swirl_file to self.files
        packages = []
        if 'ELF' in swirl_file.type and swirl_file.executable \
                and not (use_remapping and swirl_file.isLoader()):
            # executable and not a loader if we are using remppaing
            packages = self._get_package_from_dep([swirl_file.path])
        elif 'ELF' in swirl_file.type and not swirl_file.executable and not use_remapping:
            # library
            # do not process it if we are using remapping
            packages = self._get_package_from_dep(swirl_file.getPaths(), False)
        elif swirl_file.path[0] == '$' or sergeant.is_special_folder(swirl_file.path) \
                or is_special_file(swirl_file.path):
            # this file belongs to the special folders or it's a relative path
            return
        elif 'ELF' not in swirl_file.type:
            # data
            # TODO what do we do with this when we use remapping?
            packages = self._get_package_from_dep([swirl_file.path])
        if packages :
            if len(packages) > 1 :
                error_message = "The file " + swirl_file.path + " "
                error_message += "is provided by more than one RPM: " + ", ".join(packages)
                error_message += "\nAdding " + packages[0]
                logger.error(error_message)
            if swirl_file.package not in self.wanted_pcks and \
                packages[0] not in self._excluded_packages:
                self.skipped_swfs.add( swirl_file  )
                self.packages.add( packages[0] )
                # so we found a package which can handle this swf but we should still process its
                # opened file in case it is an interpreter
                self._process_open_file(swirl_file, use_remapping)
                logger.debug("Adding package " + packages[0] + " for swirl " + swirl_file.path)
                return
            else:
                self.disable_pcks |= set(packages)
        logger.debug("Adding swirl: " + swirl_file.path)
        if 'ELF' in swirl_file.type and not use_remapping:
            # for ELF swf if we select the libmpi.so.2 we also want to carry all its dynamic libraries
            # even if their name matches an available package for this reason we use wanted_pcks
            self.wanted_pcks.add(swirl_file.package)
        self.files.append(swirl_file)
        #
        # for each swf in swirlFile.all_dependencies
        #   if not already in self.files _resolve_file(swf)
        deps = self.swirl.getListSwirlFileProvide( swirl_file.staticDependencies )+\
                                swirl_file.dynamicDependencies
        for new_swf in deps:
            if new_swf not in self.files:
                #this file is already in the included files
                self._resolve_file(new_swf, use_remapping)
        self._process_open_file(swirl_file, use_remapping)


    def _process_open_file(self, swirl_file, use_remapping):
        """ scan the open files of this swirl """
        for exec_file in swirl_file.openedFiles:
            for open_file in swirl_file.openedFiles[exec_file]:
                if open_file not in self.files:
                    self._resolve_file(open_file, use_remapping)


    def _get_package_from_dep(self, package_name, match_all = True):
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
        return list(set([pkg.name + "." + pkg.arch for pkg in yum.misc.unique(matched)]))


    def _useRPMPackage(self, package_name):
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


    def _findWhoProvides(self, dependencies):
        """ """
        matches = yum.YumBase.searchPackageProvides(self, [str(depstring)])

    _graph_node_xml = '''<?xml version="1.0" standalone="no"?>
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

    _node_server_xml = '''<?xml version="1.0" standalone="no"?>
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

    _node_base_xml_top = '''<?xml version="1.0" standalone="no"?>
<kickstart>
<description>
FingerPrint
</description>
'''
    _node_base_xml_bottom = '''
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


def make_mapping_file(sw_files, output_file, base_path):
	""" this function makes a mapping file for the remapper process"""
	file_desc = open(output_file, 'w')
	for swf in sw_files:
		if getattr(swf, 'executable', False):
			# this should not be in the mapping file
			# since executable are left in the original path
			continue
		for path in swf.getPaths():
			if path[0] != '$' and swf.md5sum:
				file_desc.write(path + '\t' + base_path[:-1] + swf.path +'\n')
	file_desc.close()



