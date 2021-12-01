#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/kernel/console.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "process.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "pagedir.h"

struct file_ptr{
    int fd;
    struct file *file;
    struct list_elem file_elem;
};

static struct lock *files_synch_lock;/*lock for synchronization between files */


static void syscall_handler (struct intr_frame *);
int get_int(int** esp);                     /* get int from the stack */
int get_unsigned(int** esp);                /* get int from the stack */
char* get_char_ptr(char ***esp);            /* get char pointer */
void* get_void_ptr(void ***esp);            /* get void pointer */
void validate_void_ptr(const void* pt);    /* check if the pointer is valid */
void get_stack_args (struct intr_frame *f, int *argv, int argc);
void validate_buffer (void *buffer, unsigned size);
void validate_converted_address(int *argv);

void
acquire_files_synch_lock()
{
  lock_acquire(files_synch_lock);
}

void
release_files_synch_lock()
{
  lock_release(files_synch_lock);
}
/* get int from the stack */
int
get_int(int** esp)
{
  return *((int*)esp);
}
/* get unsigned from the stack */
int
get_unsigned(int** esp)
{
  return *((unsigned*)esp);
}
/* get char pointer */
char*
get_char_ptr(char ***esp)
{
  return (char*)(*((int*)esp));
}
/* get void pointer */
void*
get_void_ptr(void ***esp)
{
  return (char*)(*((int*)esp));
}
/* check if the pointer is valid */
void
validate_void_ptr(const void* pt)
{
  if(pt == NULL  ||!is_user_vaddr(pt) || pt < (void *) 0x08048000)
    exit(-1);
}
void
get_stack_args (struct intr_frame *f, int *argv, int argc)
{
  int *ptr;
  for (int i = 0; i < argc; i++){
      ptr = (int *) f->esp + i + 1;
      validate_void_ptr((const void *) ptr);
      argv[i] = *ptr;
    }
}
void
validate_buffer (void *buffer, unsigned size)
{
  unsigned i;
  char *ptr  = (char * )buffer;
  for (i = 0; i < size; i++)
    {
      validate_void_ptr((const void *) ptr);
      ptr++;
    }
}
void
validate_converted_address(int *argv)
{
  void *phys_page_ptr = (void *) pagedir_get_page(thread_current()->pagedir, (const void *) argv[0]);
  if (phys_page_ptr == NULL)
    exit(-1);
  argv[0] = (int) phys_page_ptr;
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  /*check if f->esp is a valid pointer*/
  /* if(){
    exit(-1);
  } */
  /* cast f->esp in an int, then dereference it for a SYS_CODE */

  validate_void_ptr((const void *)f->esp);

  int argv[3];
  int sys_code = *(int*)f->esp;
  switch(sys_code){
    case SYS_HALT:
      halt_wrapper(f, &argv[0], 0);
      halt();
      break;
    
    case SYS_EXIT:
      exit_wrapper(f, &argv[0], 1);
      exit(argv[0]);
      break;
    
    case SYS_EXEC:
      exec_wrapper(f, &argv[0], 1);
      f->eax = exec((const char *)argv[0]);
      break;
    
    case SYS_WAIT:
      wait_wrapper(f, &argv[0], 1);
      f->eax = wait((pid_t)argv[0]);
      break;
    
    case SYS_CREATE:
      create_wrapper(f, &argv[0], 2);
      f->eax = create((const char*)argv[0], (unsigned)argv[1]);
      break;
    
    case SYS_REMOVE:
      remove_wrapper(f, &argv[0], 1);
      f->eax = remove((const char*)argv[0]);
      break;
    
    case SYS_OPEN:
      open_wrapper(f, &argv[0], 1);
      f->eax = open((const char*)argv[0]);
      break;
    
    case SYS_FILESIZE:
      filesize_wrapper(f, &argv[0], 1);
      f->eax = filesize(argv[0]);
      break;
    
    case SYS_READ:
      read_wrapper(f, &argv[0], 3);
      f->eax = read(argv[0], (void*)argv[1], (unsigned)argv[2]);
      break;

    case SYS_WRITE:
      write_wrapper(f, &argv[0], 3);
      f->eax = write(argv[0], (void*)argv[1], (unsigned)argv[2]);
      break;

    case SYS_SEEK:
      seek_wrapper(f, &argv[0], 2);
      seek(argv[0], (unsigned int)argv[1]);
      break;

    case SYS_TELL:
      tell_wrapper(f, &argv[0], 1);
      f->eax = tell(argv[0]);
      break;

    case SYS_CLOSE:
      close_wrapper(f, &argv[0], 1);
      close(argv[0]);
      break;
    
    default:
      exit(-1);
  }
}
/* Actual system call and synch logic and any other logic */
/* Related to kernel space logic */

/* Terminates Pintos */
void
halt(void)
{
  shutdown_power_off();
}

void
halt_wrapper(struct intr_frame *f UNUSED, int *argv UNUSED, int argc UNUSED)
{

}

/* Terminates the current user program, returning status to the kernel. If the process’s parent waits for it (see below), this is the status that will be returned. Conventionally, a status of 0 indicates success and nonzero values indicate errors. */
void
exit(int status )
{
	thread_current()->exit_status = status;
	if(thread_current()->parent->waiting_on_thread == thread_current()->tid)
		sema_up(&thread_current()->parent->wait_child);
  printf("%s: exit(%d)\n", thread_current()->name, status);
  /* should I add this to free resources?? */
  //process_exit();
  thread_exit();
}
void
exit_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
}
/* Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process’s program ID (pid). Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this. */
pid_t
exec(const char * cmd_line)
{
  acquire_files_synch_lock();
  pid_t pid = process_execute(cmd_line);
  release_files_synch_lock();
  return pid;
}
void
exec_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
  validate_converted_address(argv);
}
/* Waits for a child process pid and retrieves the child’s exit status. */
/*  */
int
wait(pid_t pid)
{
  return process_wait(pid);
}
void
wait_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
}
/* Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. Creating a new file does not open it: opening the new file is a separate operation which would require a open system call. */
bool
create (const char * file, unsigned initial_size)
{
  acquire_files_synch_lock();
  bool status = filesys_create(file, initial_size);
  release_files_synch_lock();
  return status;
}
void
create_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
  validate_buffer((void *)argv[0], argv[1]);
  validate_converted_address(argv);
}

/* Deletes the file called file. Returns true if successful, false otherwise. A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. */
bool
remove (const char * file )
{
  acquire_files_synch_lock();
  bool status = filesys_remove(file);
  release_files_synch_lock();
  return status;
}
void
remove_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
  validate_converted_address(argv);
}

/* Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened. */
/*  */
int
open (const char * file )
{
  acquire_files_synch_lock();
  struct file *f = filesys_open(file);
  if(f == NULL){
    release_files_synch_lock();
    return -1;
  }
  struct file_ptr *temp = malloc(sizeof(struct file_ptr));
  temp->file = f;
  temp->fd = thread_current()->fd_last++;
  list_push_back (&thread_current()->files, &temp->file_elem);
  release_files_synch_lock();
  return temp->fd;
}
void
open_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
  validate_converted_address(argv);
}

/* Returns the size, in bytes, of the file open as fd. */
int
filesize (int fd )
{
  acquire_files_synch_lock();
  for(struct list_elem *e = list_begin(&thread_current()->files);
                        e!=list_end(&thread_current()->files);
                        e = list_next(e)){
    struct file_ptr *temp = list_entry(e, struct file_ptr, file_elem);
    if(temp->fd == fd){
      int bytes = (int)file_length(temp->file);
      release_files_synch_lock();
      return bytes;
    }
  }
  release_files_synch_lock();
  return -1;
}
void
filesize_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
}

/* Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc(). */
int
read (int fd , void * buffer , unsigned size )
{
  acquire_files_synch_lock();
  if(fd==0){
    release_files_synch_lock();
    return (int)input_getc();
  }
  if(fd==1){
    release_files_synch_lock();
    return 0;
  }
  for(struct list_elem *e = list_begin(&thread_current()->files);
                        e!=list_end(&thread_current()->files);
                        e = list_next(e)){
    struct file_ptr *temp = list_entry(e, struct file_ptr, file_elem);
    if(temp->fd == fd){
      int bytes = (int)file_read(temp->file, buffer, size);
      release_files_synch_lock();
      return bytes;
    }
  }
  release_files_synch_lock();
  return -1;
}
void
read_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
  validate_buffer((void *)argv[1], argv[2]);
  validate_converted_address(argv);
}

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written. */
/*  */
int write
(int fd , const void * buffer , unsigned size )
{
  acquire_files_synch_lock();
  if(fd==1){ 
    release_files_synch_lock();
    putbuf(buffer, size);
    return size;
  }
  if(fd==0){
    release_files_synch_lock();
    return 0;
  }
  for(struct list_elem *e = list_begin(&thread_current()->files);
                        e!=list_end(&thread_current()->files);
                        e = list_next(e)){
    struct file_ptr *temp = list_entry(e, struct file_ptr, file_elem);
    if(temp->fd == fd){
      int bytes = (int)file_write(temp->file, buffer, size);
      release_files_synch_lock();
      return bytes;
    }
  }
  release_files_synch_lock();
  return -1;
}
void
write_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
  validate_buffer((void *)argv[1], argv[2]);
  validate_converted_address(argv);
}

/* Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file’s start.) */
/*  */
void
seek (int fd , unsigned position)
{
  acquire_files_synch_lock();
  for(struct list_elem *e = list_begin(&thread_current()->files);
                        e!=list_end(&thread_current()->files);
                        e = list_next(e)){
    struct file_ptr *temp = list_entry(e, struct file_ptr, file_elem);
    if(temp->fd == fd){
      file_seek(temp->file, position);
      release_files_synch_lock();
      return;
    }
  }
  release_files_synch_lock();
}
void
seek_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
}


/* Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file. */
unsigned
tell (int fd )
{
  acquire_files_synch_lock();
  for(struct list_elem *e = list_begin(&thread_current()->files);
                        e!=list_end(&thread_current()->files);
                        e = list_next(e)){
    struct file_ptr *temp = list_entry(e, struct file_ptr, file_elem);
    if(temp->fd == fd){
      unsigned pos = file_tell(temp->file);
      release_files_synch_lock();
      return pos;
    }
  }
  release_files_synch_lock();
  return -1;
}
void
tell_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one. */
void
close(int fd)
{
  acquire_files_synch_lock();
  for(struct list_elem *e = list_begin(&thread_current()->files);
                        e!=list_end(&thread_current()->files);
                        e = list_next(e)){
    struct file_ptr *temp = list_entry(e, struct file_ptr, file_elem);
    if(temp->fd == fd){
      file_close(temp->file);
      release_files_synch_lock();
      return;
    }
  }
  release_files_synch_lock();
}
void
close_wrapper(struct intr_frame *f, int *argv, int argc)
{
  get_stack_args(f, argv, argc);
}


