/* 
 *
 */

#include "Python.h"


/* A static module */

/* 'self' is not used */
static PyObject *
trace_method(PyObject *self, PyObject* args)
{

    char * pid;
    if (!PyArg_ParseTuple(args, "s", pid))
            return NULL;
    printf("%s\n", pid);

    //unw_word_t ip;
    //int n = 0, ret;
    //unw_cursor_t c;
  
    //extern unw_addr_space_t libunwind_as;
    //if (unw_init_remote(&c, libunwind_as, tcp->libunwind_ui) < 0){
    //    //TODO return errror
    //    perror_msg_and_die("Unable to initiate libunwind");
    //}
    //do {
    //  if (unw_get_reg(&c, UNW_REG_IP, &ip) < 0)
    //      perror_msg_and_die("Unable to walk the stack of process %d", tcp->pid);
  
    //  print_normalized_addr(tcp, ip);
  
    //  ret = unw_step(&c);
  
    //  if (++n > 255) {
    //    /* guard against bad unwind info in old libraries... */
    //    perror_msg("libunwind warning: too deeply nested---assuming bogus unwind\n");
    //    break;
    //  }
    //} while (ret > 0);

    //// Py_BuildValue("{s:i,s:i}", "abc", 123, "def", 456)
    ////    {'abc': 123, 'def': 456}
    return Py_BuildValue("s", "/bin/mybin");
}




static PyMethodDef stracktracer_methods[] = {
    {"trace",             trace_method,      METH_NOARGS,
     "Return the stack of the process specified by the PID."},
    {NULL,              NULL}           /* sentinel */
};


void
initstacktracer(void)
{
    PyImport_AddModule("stracktracer");
    Py_InitModule("stracktracer", stracktracer_methods);
}


