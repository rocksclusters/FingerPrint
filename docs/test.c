//
// orrible code I used to test the ptrace syscal sequence 
// while writing the syscalltrace.py copied here only not 
// to delete it
//

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/syscall.h>   



int main() {
    pid_t child;
    long options =  PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD;
    long children[100];
    int numChildren;
    int event;
    int status;
    struct user_regs_struct uregs;
    //max num of subprocess
    int enter[10];
    child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	char * args[] = {"ls"};
        //execve("/bin/ls", args, NULL);
        //execl("/bin/ls", "ls", NULL);
        execl("/bin/bash", "/bin/bash", "-c", "sleep 5 & ls > crap2 & find /tmp 1> crap &", NULL);
    }
    else {
       printf("process %d tracing %d\n", getpid(), child);
       if (wait(&status) != child)
           printf("wait did not return what we expected\n");
       int a = ptrace(PTRACE_SETOPTIONS, child, 0 , options);
       int b = ptrace(PTRACE_SYSCALL, child, 0, 0);
       printf("ptracing %d entrering the loop. %d %d\n", child, a, b);

       while(1) {
          child = wait(&status);
          if (! (child > 0)) {
               printf("we are broke.\n");
               break;
          }

          event = ((unsigned)status >> 16);
          //printf("the child process %d stops. status: %d, signal? %d, exit? %d, continue? %d, stop? %d\n" ,
          //    child, status , WIFSIGNALED(status) ,
          //    WIFEXITED(status) , WIFCONTINUED(status) , WSTOPSIG(status));

          
          if (WIFSTOPPED(status) && (WSTOPSIG(status) == ( SIGTRAP | 0x80))) {
              // we used sysgood so syscall are sigtrap | 0x80
              ptrace(PTRACE_GETREGS, child, 0, &uregs);
              // should be orig_eax if 32 bit
              //printf("the process %d made syscall %d\n", child, uregs.orig_rax );
              if (uregs.orig_rax == 9) 
                  printf("the process %d made syscall mmap\n");
          } 
          else if(WIFSTOPPED(status) && (WSTOPSIG(status) == SIGTRAP)){

              pid_t subChild;
              ptrace(PTRACE_GETEVENTMSG, child,  NULL, &subChild);
              //printf("the ptrace getenvent is %d\n", subChild);

              //if(status & (SIGTRAP | PTRACE_EVENT_CLONE << 8)){
              //    printf("the child process clone a new process\n");
              //} else
              //printf("status is: %d event %d\n", status, event);
              //if ()
              if(event == PTRACE_EVENT_EXIT){
                  printf("process %d exiting (getmessage %d)\n", child, subChild);
              } else if(event == PTRACE_EVENT_FORK ){
                  printf("the process %d fork a new process %d\n", child, subChild);
                  //ptrace(PTRACE_SETOPTIONS, subChild, 0 , options);
                  //ptrace(PTRACE_CONT, subChild, 0, 0);
                  //if ( ptrace(PTRACE_SETOPTIONS, subChild, 0 , options) == -1) {
                  //    printf("error in the fork ptrace set opt: %d\n", errno);
                  //}
                  //if ( ptrace(PTRACE_CONT, subChild, 0, 0) == -1) {
                  //    printf("error in the fork ptrace cont: %d\n", errno);
                  //}
              } else if(event == PTRACE_EVENT_VFORK){
                  printf("the child process %d vfork a new process %d\n", child, subChild);
                  //ptrace(PTRACE_SETOPTIONS, subChild, 0 , options);
                  //ptrace(PTRACE_CONT, subChild, 0, 0);
              } else if(event == PTRACE_EVENT_CLONE){
                  printf("the child process %d cloned a new process %d\n", child, subChild);
                  //ptrace(PTRACE_SETOPTIONS, subChild, 0 , options);
                  //ptrace(PTRACE_CONT, subChild, 0, 0);
              } else if(event == PTRACE_EVENT_EXEC){
                  printf("the child process %d execd %d\n", child, subChild);
              }
          }else 
              printf("not a stopped signal\n");

          ptrace(PTRACE_SETOPTIONS, child, 0 , options);
          ptrace(PTRACE_SYSCALL, child, 0, 0);
        }
    }
    return 0;
}
