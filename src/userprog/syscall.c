#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  uint16_t *esp = f->esp;
  printf("esp: %hn\n", esp);
  if (esp == SYS_EXIT) 
  {
    exit(-1);
  } 
  else if (*esp == SYS_READ) 
  {
    printf("Read system call, exiting...");
    thread_exit();
  } 
  else if (esp == SYS_WRITE)
  {
    printf("Read system call, exiting...");
    thread_exit();
  }


  printf ("system call!\n");
  thread_exit ();
}

void exit (int status) 
{
  printf("Exit system call, exiting...");
  thread_exit();
}

int read (int fd, void *buffer, unsigned length) 
{
  printf("Read system call, exiting...");
  thread_exit();
}


int write (int fd, const void *buffer, unsigned length)
{
  printf("Write system call, exiting...");
  thread_exit();
}


