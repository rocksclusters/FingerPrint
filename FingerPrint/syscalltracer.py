#!/usr/bin/env python
#
#
# LC
#
# this file is used to trace a process and to see what are the 
# libraries it depends on
#

import sys
sys.path.append('.')
from ptrace.binding import func as ptrace_func
import ptrace

from logging import (getLogger, DEBUG, INFO, WARNING, ERROR)

import FingerPrint

import os, signal

class SyscallTracer:
    """this class can spawn a process and trace its' execution to check 
    what are its dynamic dependency requirements

    Usage:

        tracer = SyscallTracer()
        execcmd = shlex.split(execcmd)
        tracer.main(execcmd, dynamicDependecies)

    dynamicDependencies is a dictionary of 
    { 'binarypath' : [list of file it depends to],
    '/bin/bash' : ['/lib/x86_64-linux-gnu/libnss_files-2.15.so',
    '/lib/x86_64-linux-gnu/libnss_nis-2.15.so']}

    """

    def main(self, command, dependencies):
        #
        # main function to launch a process and trace it
        #
        self.dependencies = dependencies
        returnValue = False
        self.program = command
        # this is to check if we are entering or returning from a system call
        syscallEnter = dict()
        options =  ptrace_func.PTRACE_O_TRACEFORK | ptrace_func.PTRACE_O_TRACEVFORK \
                | ptrace_func.PTRACE_O_TRACECLONE | ptrace_func.PTRACE_O_TRACEEXIT \
                | ptrace_func.PTRACE_O_TRACEEXEC | ptrace_func.PTRACE_O_TRACESYSGOOD;
        #logger = getLogger()
        #logger.setLevel(DEBUG)
        # creating the debugger and setting it up
        child = os.fork()
        if child == 0:
            # we are in the child
            #tracem and execv
            ptrace_func.ptrace_traceme()
            os.execl(ptrace.tools.locateProgram(self.program[0]), *self.program)
        else:
            print "process %d tracing %d" % (os.getpid(), child)
            pid, status = os.waitpid(-1, 0)
            if pid != child :
                print("wait did not return what we expected")
            
            ptrace_func.ptrace_setoptions(child, options);
            ptrace_func.ptrace_syscall(child);
            print("ptracing %d entrering the loop.\n" % child);
            
            while True: 
                try:
                    (child, status) = os.waitpid(-1, 0)
                except OSError:
                    print "Tracing terminated"
                    break
                if not child > 0:
                    print "catastrofic failure"
                    break
                event = status >> 16;

                #print "the child process %d stops. status: %d, signal? %d, exit? %d, continue? %d, stop? %d\n" % \
                #    (child, status , os.WIFSIGNALED(status) ,
                #    os.WIFEXITED(status), os.WIFCONTINUED(status), os.WIFSTOPPED(status))

                if os.WIFEXITED(status):
                    print "process ", child, " terminating"
                    continue


                if os.WIFSTOPPED(status) and (os.WSTOPSIG(status) == (signal.SIGTRAP | 0x80 )):
                    regs = ptrace_func.ptrace_getregs(child)
                    if regs.orig_rax == 9 :
                        # syscall
                        if child not in syscallEnter.keys() :
                            #new pid
                            syscallEnter[child] = True
                        if syscallEnter[child] :
                            # we are entering
                            syscallEnter[child] = False
                            #print "the process %d enter mmap" % child
                        else:
                            syscallEnter[child] = True
                            print "the process %d exit mmap" % child
                elif os.WIFSTOPPED(status) and (os.WSTOPSIG(status) == signal.SIGTRAP) :
                    #TODO detect capability
                    subChild = ptrace_func.ptrace_geteventmsg(child)
                    if event == ptrace_func.PTRACE_EVENT_FORK:
                        print "the process %d fork a new process %d" % (child, subChild)
                    elif event == ptrace_func.PTRACE_EVENT_VFORK:
                        print "the process %d vfork a new process %d" % (child, subChild)
                    elif event == ptrace_func.PTRACE_EVENT_CLONE :
                        print "the child process %d cloned a new process %d" % (child, subChild)
                    elif event == ptrace_func.PTRACE_EVENT_EXEC :
                        print "the child process %d execd %d" % (child, subChild)
                    elif event == ptrace_func.PTRACE_EVENT_EXIT:
                        pass
                        #print "the process %d is in a event exit %d" % (child, subChild)
                
                ptrace_func.ptrace_setoptions(child, options);
                ptrace_func.ptrace_syscall(child);


    def test(self):
        
        self.main(["bash", "-c", "sleep 5 & find /tmp > /dev/null &"], dict())

if __name__ == "__main__":
    SyscallTracer().test()

