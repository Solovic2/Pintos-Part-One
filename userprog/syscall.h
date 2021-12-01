#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/user/syscall.h"
#include "threads/interrupt.h"

void acquire_files_synch_lock(void);
void release_files_synch_lock(void);


void syscall_init (void);

void halt(void);
void exit(int status );
pid_t exec(const char * cmd_line);
int wait(pid_t pid);
bool create (const char * file, unsigned initial_size);
bool remove (const char * file );
int open (const char * file );
int filesize (int fd );
int read (int fd , void * buffer , unsigned size );
int write (int fd , const void * buffer , unsigned size );
void seek (int fd , unsigned position );
unsigned tell (int fd );
void close(int fd );

void halt_wrapper(struct intr_frame *f, int *argv, int argc);
void exit_wrapper(struct intr_frame *f, int *argv, int argc);
void exec_wrapper(struct intr_frame *f, int *argv, int argc);
void wait_wrapper(struct intr_frame *f, int *argv, int argc);
void create_wrapper(struct intr_frame *f, int *argv, int argc);
void remove_wrapper(struct intr_frame *f, int *argv, int argc);
void open_wrapper(struct intr_frame *f, int *argv, int argc);
void filesize_wrapper(struct intr_frame *f, int *argv, int argc);
void read_wrapper(struct intr_frame *f, int *argv, int argc);
void write_wrapper(struct intr_frame *f, int *argv, int argc);
void seek_wrapper(struct intr_frame *f, int *argv, int argc);
void tell_wrapper(struct intr_frame *f, int *argv, int argc);
void close_wrapper(struct intr_frame *f, int *argv, int argc);
#endif /* userprog/syscall.h */
