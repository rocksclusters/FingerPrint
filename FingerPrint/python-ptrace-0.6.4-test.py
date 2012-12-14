#!/usr/bin/env python
from ptrace import PtraceError
from ptrace.debugger import (PtraceDebugger, Application,
    ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from ptrace.func_call import FunctionCallOptions
from sys import stderr, exit
import os
from ptrace.ctypes_tools import formatAddress
import ptrace.tools 
import ptrace.debugger.child


class SyscallTracer():


    def displaySyscall(self, syscall):
        name = syscall.name
        text = syscall.format()
        if syscall.result is not None:
            text = "%-40s = %s" % (text, syscall.result_text)
        prefix = []
        prefix.append("[%s]" % syscall.process.pid)
        prefix.append("[%s]" % formatAddress(syscall.instr_pointer))
        text = ''.join(prefix) + ' ' + text
        print(text)
        #print "syscall: " , dir(syscall)
        #print "syscall: " , 
        #os.system("cat /proc/" + str(syscall.process.pid) + "/maps")


    def createProcess(self):
        #if self.options.pid:
        #    pid = self.options.pid
        #    is_attached = False
        #    error("Attach process %s" % pid)
        #else:
        #    pid = self.createChild(self.program)
        #    is_attached = True
        pid = ptrace.debugger.child.createChild(self.program, False, None)
        is_attached = True
        try:
            return self.debugger.addProcess(pid, is_attached=is_attached)
        except (ProcessExit, PtraceError), err:
            if isinstance(err, PtraceError) \
            and err.errno == EPERM:
                print("ERROR: You are not allowed to trace process %s (permission denied or process already traced)" % pid)
            else:
                print("ERROR: Process can no be attached! %s" % err)
        return None


    def prepareProcess(self, process):
        process.syscall()
        process.syscall_state.ignore_callback = self.ignoreSyscall


    def syscallTrace(self, process):
        # First query to break at next syscall
        self.prepareProcess(process)

        while True:
            # No more process? Exit
            if not self.debugger:
                break

            # Wait until next syscall enter
            try:
                event = self.debugger.waitSyscall()
                process = event.process
            except ProcessExit, event:
                self.processExited(event)
                continue
            except ProcessSignal, event:
                event.display()
                process.syscall(event.signum)
                continue
            except NewProcessEvent, event:
                # newProcess (event)
                process = event.process
                print("*** New process %s ***" % process.pid)
                self.prepareProcess(self, process)
                process.parent.syscall()
                continue
            except ProcessExecution, event:
                #execv
                process = event.process
                print("*** Process %s execution ***" % process.pid)
                process.syscall()
                continue

            # Process syscall enter or exit
            self.syscall(process)

    def syscall(self, process):
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        if syscall and (syscall.result is not None ):
            self.displaySyscall(syscall)
        # Break at next syscall
        process.syscall()

    def processExited(self, event):
        # Display syscall which has not exited
        state = event.process.syscall_state
        if (state.next_event == "exit") \
        and state.syscall:
            self.displaySyscall(state.syscall)
        # Display exit message
        print("*** %s ***" % event)


    def ignoreSyscall(self, syscall):
        #what other functions we want to trace
        if not syscall.name == 'mmap' and \
            not syscall.name.startswith('exec'):
            return True


    def main(self):
        self.program = ["bash","-c","/usr/bin/find /tmp"]
        self.program[0] = ptrace.tools.locateProgram(self.program[0])
        self.debugger = PtraceDebugger()
        try:
            self.debugger.traceFork()
            self.debugger.traceExec()
            process = self.createProcess()
            if not process:
                return

            self.syscall_options = FunctionCallOptions(
                write_types=True,
                write_argname=True,
                string_max_length=300,
                replace_socketcall=True,
                write_address=True,
                max_array_count=300
            )
            self.syscall_options.instr_pointer = True
            self.syscallTrace(process)
        except ProcessExit, event:
            self.processExited(event)
        except PtraceError, err:
            print("ptrace() error: %s" % err)
        except KeyboardInterrupt:
            print("Interrupted.")
        self.debugger.quit()

if __name__ == "__main__":
    SyscallTracer().main()









