#!/usr/bin/python
#
# LC
#
# This class create swirl starting from binaries, command lines, 
# or process number
#

from datetime import datetime
import subprocess
import os
#TODO remove shlex for python 2.4
import shlex

#
# compatibility with python2.4
#
try:
    from hashlib import md5
except ImportError:
    from md5 import md5

#
# compatibility with python2.4
#
if "any" not in dir(__builtins__):
    from FingerPrint.utils import any

from swirl import Swirl, SwirlFile
import sergeant, utils
from FingerPrint.plugins import PluginManager
from FingerPrint.utils import getOutputAsList

import FingerPrint.syscalltracer



class Blotter:
    """
    This class creates a swirl file starting from:
     - a list of binaries
     - command lines that we want to execute and trace
     - a list of pids
    """

    def __init__(self, name, fileList, processIDs, execCmd):
        """give a file list and a name construct a swirl into memory """
        self._detectedPackageManager() 
        self.swirl = Swirl(name, datetime.now())
        if execCmd :
            self.swirl.cmdLine = execCmd
        # 
        # dependencies discovered with dinamic methods
        # dynamicDependencies = { 'binarypath' : [list of file it depends to],
        # '/bin/bash' : ['/lib/x86_64-linux-gnu/libnss_files-2.15.so',
        # '/lib/x86_64-linux-gnu/libnss_nis-2.15.so']}

        if execCmd :
            self._straceCmd(execCmd)

        # let's see if we have proecss ID we might need to scan for dynamic dependecies
        # with the help of the /proc FS
        elif processIDs :

            for proc in processIDs.split(','):
                pid = proc.strip()
                # add the binary
                tcb = FingerPrint.syscalltracer.TracerControlBlock(pid)
                tcb.updateSharedLibraries()

        dynamicDependecies = FingerPrint.syscalltracer.TracerControlBlock.dependencies
        # set up the fileList for the static dependency detection
        if not fileList :
            fileList = []
        fileList = fileList + dynamicDependecies.keys()
        # add all the fileList to the swirl and figure out all their static libraries
        for i in fileList:
            if os.path.isfile(i):
                cmd = i
                if i in FingerPrint.syscalltracer.TracerControlBlock.cmdline:
                    # the user cmdline could be a symlink so we want to keep track
                    cmd = FingerPrint.syscalltracer.TracerControlBlock.cmdline[i][0]
                    cmd = utils.which(cmd)
                    if not cmd :
                        cmd = i
                swirlFile = PluginManager.getSwirl(cmd, self.swirl)
                # add the env
                if i in FingerPrint.syscalltracer.TracerControlBlock.env:
                    process_env = FingerPrint.syscalltracer.TracerControlBlock.env[i]
                    for i in process_env:
                        if  i.startswith('PATH') or i.startswith('LD_LIBRARY_PATH') or \
                            i.startswith('LD_PRELOAD'):
                            swirlFile.env.append(i)
                self.swirl.execedFiles.append(swirlFile)

            elif os.path.isdir(i):
                pass
            else:
                raise IOError("The file %s cannot be opened." % i)
        #
        # we might need to add the dynamic dependencies to the swirl
        # if they did not get detected already
        for fileName in dynamicDependecies.keys():
            swirlFile = PluginManager.getSwirl(fileName, self.swirl)
            #let's add it to the execed file list
            if swirlFile not in self.swirl.execedFiles:
                self.swirl.execedFiles.append(swirlFile)
            for dynamicDepFile in dynamicDependecies[fileName]:
                newSwirlFileDependency = PluginManager.getSwirl(dynamicDepFile, self.swirl)
                #I need to verify it if is static dep or dynamic dep
                #TODO need to optimize this
                swirlDependencies = self.swirl.getListSwirlFilesDependentStatic( swirlFile )
                if newSwirlFileDependency.path not in [x.path for x in swirlDependencies]:
                    swirlFile.dynamicDependencies.append(newSwirlFileDependency)

        # let's see if it used some Data files
        # files is a double dictionary see TraceContrlBlock for its structure
        files = FingerPrint.syscalltracer.TracerControlBlock.files
        # excludeFileName: file whcih should be ingored and not added to the swirl
        excludeFileName = ['/etc/ld.so.cache']
        for lib_swFile in files:
            swirlFile = self.swirl.createSwirlFile(lib_swFile)
            if swirlFile.isLoader() :
                continue
            all_dependencies_files=[]
            #TODO take this for loop out of the for lib_swFile loop
            for deps in self.swirl.getListSwirlFilesDependentStaticAndDynamic(swirlFile):
                all_dependencies_files += deps.getPaths()
            for execFile in files[lib_swFile]:
                for openedFile in files[lib_swFile][execFile]:
                    # we need to remove some useless files from the opened list
                    # if not depenedencies will be listed as opned files
                    if openedFile not in excludeFileName and not os.path.isdir(openedFile):
                        swirlOpenedFile = self.swirl.createSwirlFile(openedFile)
                        if swirlOpenedFile.path not in all_dependencies_files:
                            if execFile not in swirlFile.openedFiles:
                                swirlFile.openedFiles[execFile] = []
                            swirlFile.openedFiles[execFile].append(swirlOpenedFile)
        #hash and get package name
        for swf in self.swirl.swirlFiles:
            #let's skip relative path
            if swf.path[0] != '$' and os.path.exists(swf.path):
                swf.md5sum = sergeant.getHash(swf.path, swf.type)
                #TODO make this code nicer
                if any([ swf.path.startswith(a) for a in sergeant.specialFolders ]):
                    swf.package = None
                else:
                    swf.package = self._getPackage(swf.path)


    def getSwirl(self):
        """return the current swirl """
        return self.swirl 


    #TODO add a way to detach from executed programm
    def _straceCmd(self, execcmd):
        """it execute the execmd with execve and then it trace process running and
        it adds all the dependency to the dynamicDependecies dictionary
        """
        tracer = FingerPrint.syscalltracer.SyscallTracer()
        #TODO check for errors
        execcmd = shlex.split(execcmd)
        try:
            if not tracer.main(execcmd):
                raise IOError("Unable to trace the process")
        except ImportError, e:
            raise IOError("Dynamic tracing is not supported on this platform (you need "
                    "python2.7 or ctype for dynamic tracing): ", e)




    #
    # package manager related suff
    # TODO move into their own class
    #
    def _detectedPackageManager(self):
        """ set the proper _getPackage*(self, path)
        function to handle rpm or dpkg based on /etc/issue content"""
        #rpm based OSes
        rpmOSs = ["red hat", "fedora", "suse", "centos", "scientific linux"]
        #dpkg based OSes
        dpkgOSs = ["debian",  "ubuntu"]

        f=open('/etc/issue.net')
        issues=f.read()
        f.close()
        if any(os in issues.lower() for os in rpmOSs):
            self._getPackage = self._getPackageRpm
        if any(os in issues.lower() for os in dpkgOSs):
            self._getPackage = self._getPackageDpkg
        if not '_getPackage' in dir(self):
            #we could not detect the pakcage manager
            self._getPackage = lambda  p : None


    def _getPackageDpkg(self, path):
        """given a path it return the package which provide that 
        path if if finds one only debian system"""
        cmd1 = ['dpkg', '-S']
        cmd2 = ['dpkg-query', '--show', "-f=${Package}\ ${Version}\ ${Architecture}", ]
        try:
            (package, returncode) = getOutputAsList(cmd1 + [path])
        except subprocess.CalledProcessError:
            #package not found
            return None
        except OSError:
            #cmd not found
            return None
        if returncode != 0 or len(package[0]) == 0:
            #the file is not tracked
            return None
        packageName = package[0].split(':')[0]
        try:
            (package, returncode) = getOutputAsList(cmd2 + [packageName])
            if returncode != 0:
                return None
            return package[0]
        except subprocess.CalledProcessError:
            #package not found
            return None
        except OSError:
            #cmd not found
            return None

    def _getPackageRpm(self, path):
        """given a path it return the package which provide that 
        path if if finds one
        only rpm based system"""
        cmd = ['rpm', '-qf']
        try:
            (package, returncode) = getOutputAsList(cmd + [path])
            if returncode != 0:
                return None
            return package[0]
        except subprocess.CalledProcessError:
            #package not found
            return None
        except OSError:
            #cmd not found
            return None
        


