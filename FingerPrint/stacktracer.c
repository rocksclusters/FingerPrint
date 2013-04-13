/* 
 * A static method used only for backtracing the stack of a running process
 */

#include <Python.h>
#include <libunwind-ptrace.h>
#include <stdbool.h>


struct mmap_cache_t {
    // example entry:
    // 7fabbb09b000-7fabbb09f000 r--p 00179000 fc:00 1180246 /lib/libc-2.11.1.so
    //
    // start_addr  is 0x7fabbb09b000
    // end_addr    is 0x7fabbb09f000
    // mmap_offset is 0x179000
    // binary_filename is "/lib/libc-2.11.1.so"
    unsigned long start_addr;
    unsigned long end_addr;
    unsigned long mmap_offset;
    char* binary_filename;
};

struct mmap_cache_t * mmap_cache;
int mmap_cache_size;


/**
 * cache the memory maped areas
 *
 * TODO bool is not portable
 */
bool alloc_mmap_cache(int pid) {

    // start with a small dynamically-allocated array and then use realloc() to
    // dynamically expand as needed
    int cur_array_size = 10;
    struct mmap_cache_t* cache_head = malloc(cur_array_size * sizeof(*cache_head));
    mmap_cache_size = 0;

    char filename[30];
    sprintf(filename, "/proc/%d/maps", pid);

    FILE* f = fopen(filename, "r");
    if ( ! f ){
        PyErr_SetString(PyExc_MemoryError, "Unable to open maps file");
        return false;
    }
    char s[300];
    while (fgets(s, sizeof(s), f) != NULL) {
        unsigned long start_addr, end_addr, mmap_offset;
        char binary_path[512];
        binary_path[0] = '\0'; // 'reset' it just to be paranoid

        sscanf(s, "%lx-%lx %*c%*c%*c%*c %lx %*x:%*x %*d %[^\n]", &start_addr, &end_addr, &mmap_offset, binary_path);

        // there are some special 'fake files' like "[vdso]", "[heap]", "[stack]",
        // etc., so simply IGNORE those!
        if (binary_path[0] == '[' && binary_path[strlen(binary_path) - 1] == ']') {
          continue;
        }

        // empty string
        if (binary_path[0] == '\0') {
          continue;
        }

        if(end_addr < start_addr){
            PyErr_SetString(PyExc_MemoryError, "maps is corrupted");
            return false;
        }

        struct mmap_cache_t* cur_entry = &cache_head[mmap_cache_size];
        cur_entry->start_addr = start_addr;
        cur_entry->end_addr = end_addr;
        cur_entry->mmap_offset = mmap_offset;
        cur_entry->binary_filename = strdup(binary_path);

        // sanity check to make sure that we're storing non-overlapping regions in
        // ascending order:
        if (mmap_cache_size > 0) {
          struct mmap_cache_t* prev_entry = &cache_head[mmap_cache_size - 1];
          if (prev_entry->start_addr >= cur_entry->start_addr){
              PyErr_SetString(PyExc_MemoryError, "Problem with decoding mmaps1");
              return false;
          }
          if (prev_entry->end_addr > cur_entry->start_addr){
              char tmpbus[200];
              sprintf(tmpbus, "file %lx %lx ", prev_entry->end_addr, cur_entry->start_addr);
              PyErr_SetString(PyExc_MemoryError, tmpbus);//"Problem with decoding mmaps2");
              return false;
          }
        }
        mmap_cache_size++;

        // resize:
        if (mmap_cache_size >= cur_array_size) {
          cur_array_size *= 2; // double in size!
          cache_head = realloc(cache_head, cur_array_size * sizeof(*cache_head));
        }
    }
    fclose(f);

    mmap_cache = cache_head;
    return true;
}

/* deleting the cache */
void delete_mmap_cache(void) {
  int i;
  for (i = 0; i < mmap_cache_size; i++) {
    free(mmap_cache[i].binary_filename);
  }
  if ( mmap_cache ) 
    free(mmap_cache);
  mmap_cache = NULL;
  mmap_cache_size = 0;
}


//make this a #define
static PyObject *
perror_msg_and_die(char * error_msg){
    PyErr_SetString(PyExc_MemoryError, error_msg);
    return NULL;
}



/* Pseudo FILE object for strings.  */
typedef struct
{
    char *buffer;
    size_t pos;
    size_t alloc;
} SFILE;




int
custom_fprintf(SFILE * f, const char * format, ...)
{
    size_t n = 0;
    va_list args;
    while (1)
    {
        size_t space = f->alloc - f->pos;
        va_start (args, format);
        n = vsnprintf (f->buffer + f->pos, space, format, args);
        va_end (args);
        if (space > n)
            break;

        f->alloc = (f->alloc + n) * 2;
        f->buffer = (char *) realloc (f->buffer, f->alloc);
        if ( ! f->buffer )
            perror_msg_and_die("Error extending print buffer");
    }
    f->pos += n;
    return n;
}



#define MAX_STACK 255
#define MAX_STRING 255

/* 'self' is not used */
static PyObject *
trace_method(PyObject *self, PyObject* args)
{

    int pid;
    //initialize the buffer
    SFILE buffer;
    buffer.buffer = malloc(50);
    buffer.alloc = 50;
    buffer.pos = 0;

    if (!PyArg_ParseTuple(args, "i", &pid))
            return NULL;

    int n = 0, ret;
    char * return_val[MAX_STACK];

    unw_word_t ip;
    unw_cursor_t c;
    unw_addr_space_t libunwind_as = unw_create_addr_space (&_UPT_accessors, 0);
    struct UPT_info* libunwind_ui = _UPT_create(pid);
    if (unw_init_remote(&c, libunwind_as, libunwind_ui) < 0)
        return perror_msg_and_die("Unable to initiate libunwind");

    if ( ! alloc_mmap_cache(pid) ){
        //error was set in alloc_mmap_cache
        return NULL;
    }

    do {
        if (unw_get_reg(&c, UNW_REG_IP, &ip) < 0)
            return perror_msg_and_die("Unable to walk the stack of process");

        // since mmap_cache is sorted, do a binary search 
        int lower = 0;
        int upper = mmap_cache_size;

        while (lower <= upper) {
            int mid = (int)((upper + lower) / 2);
            struct mmap_cache_t* cur = &mmap_cache[mid];

            if (ip >= cur->start_addr && ip < cur->end_addr) {
                // calculate the true offset into the binary ...
                // but still print out the original address because it can be useful too ...
                unsigned long true_offset;
                //watch out for binary non relocatable
                true_offset = ip - cur->start_addr + cur->mmap_offset;
                return_val[n] = malloc(sizeof(char) * MAX_STRING);
                if ( ! return_val[n] )
                    return perror_msg_and_die("Unable to allocate string memory");
                custom_fprintf(&buffer, "%s:0x%lx:0x%lx\n", cur->binary_filename, true_offset, ip);
                break;
            }
            else if (ip < cur->start_addr) {
                upper = mid - 1;
            }
            else {
                lower = mid + 1;
            }
        }//TODO handle case unmapped memory region
        //unwind another stack frame
        ret = unw_step(&c);

        if (++n > MAX_STACK) {
            /* guard against bad unwind info in old libraries... */
            return perror_msg_and_die("libunwind warning: too deeply nested---assuming bogus unwind\n");
        }
    } while (ret > 0);


    buffer.buffer[buffer.pos] = '\0';
    PyObject * returnValue = Py_BuildValue("s", buffer.buffer);
    free(buffer.buffer);
    return returnValue;
}




static PyMethodDef stracktracer_methods[] = {
    {"trace",             trace_method,      METH_VARARGS,
     "Return the stack of the process specified by the PID."},
    {NULL,              NULL}           /* sentinel */
};


void
initstacktracer(void)
{
    PyImport_AddModule("stacktracer");
    Py_InitModule("stacktracer", stracktracer_methods);
}


