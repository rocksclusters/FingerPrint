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
                '\n  '.join(self.sergeant.getErrors())
            return False
        # prepare the folders for the tar
        base_tar = tempfile.mkdtemp()
        base_dir = os.path.join(base_tar, self.archive_filename.split(".tar.gz")[0])
        exec_dir = os.path.join(base_dir, "bin")
        lib_dir = os.path.join(base_dir, "lib")
        data_dir = os.path.join(base_dir, "data")
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
            elif any([ swf.path.startswith(i) for i in sergeant.specialFolders ]):
                # this file belongs to the special folders let's skip it
                continue
            else:
                temp_path = data_dir
            shutil.copy2(swf.path, temp_path)
            for i in swf.links:
                #os.symlink(os.path.join(temp_path, os.path.basename(swf.path))
                os.symlink( os.path.basename(swf.path),
                        os.path.join(temp_path, os.path.basename(i)))
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

