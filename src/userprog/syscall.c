#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

/**
 *  TODO: Whenever a user process wants to access some kernel functinality,
 *        it invokes a system call. This is a skeleton system call handler.
 *        Currently, it just prints a message and terminates the user process.
 *        In the second part of this project you will add code to do everyting
 *        else needed by system calls.
 */
void exit (int status);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void syscall_1 (struct intr_frame *f, int syscall_number, void *arg);
void syscall_3 (struct intr_frame *f, int syscall_number, void *args);
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
syscall_1 (struct intr_frame *f UNUSED, int syscall_number, void *arg)
{
  int arg0 = *((int*)arg);

  /* Switch incase there will be further implementation */
  switch (syscall_number) {
    case SYS_EXIT:
      exit(arg0);
      break;
    default:
      printf("Not yet implemented\n");
      thread_exit();
      break;
  }
}

void
syscall_3 (struct intr_frame *f UNUSED, int syscall_number, void *args)
{
  int arg0 = *((int*)args);       // Unused for now, replaced with STDIN/STDOUT.
  int arg1 = *((int*)(args + 4));
  int arg2 = *((int*)(args + 8));

  switch (syscall_number) {
    case SYS_READ:
      f->eax = read(arg0, (void*) arg1, (unsigned) arg2);
      break;
    case SYS_WRITE:
      f->eax = write(arg0, (void*) arg1, (unsigned) arg2);
      break;
    default:
      printf("Not yet implemented\n");
      thread_exit();
      break;
  }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /*
   * The system call number is in the 32-bit word at the caller's stack pointer.
   * The first argument is in the 32-bit word at the next higher address, and so on.
   * The caller's stack pointer is accessible by the esp member of *f.
  */
  if (f == NULL) {
    printf("Invalid intr_frame\n");
    thread_exit();
  }

  int syscall_number = *((int*)f->esp);
  void *args = f->esp += 4;
    
  switch (syscall_number) {
    case SYS_EXIT:
      printf("Exit\n");
      syscall_1(f, SYS_EXIT, args);
      break;
    case SYS_READ:
      printf("Read\n");
      syscall_3(f, SYS_READ, args);
      thread_exit();
      break;
    case SYS_WRITE:
      printf("Write\n");
      syscall_3(f, SYS_WRITE, args);
      thread_exit();
      break;
    default:
      printf("This System Call (%d) is not yet supported.\n", syscall_number);
      thread_exit();
      break;
  }

}

void
exit (int status)
{
  /* Getting current thread */
  struct thread *cur = thread_current();
  cur->status = status;

  /* Need to check if current thread is a child of another thread */

  thread_exit();
}

int
read (int fd, void *buffer, unsigned length UNUSED)
{
  /* Invalid File Descriptor */
  if (fd < 0) {
    printf("Passed Invalid File Descriptor.\n");
    return -1;
  }

  /* Null Buffer */
  if (buffer == NULL) {
    printf("Passed A Null Buffer.\n");
    return -1;
  }

  /* Reading From Keyboard */
  if (fd == 0) {
    return input_getc();
  }

  /* Reading From File */
  printf("Reading from anything but STDIN not yet implemented.\n");
  return -1;
}

int
write (int fd, const void *buffer, unsigned length)
{
  /* Invalid File Descriptor */
  if (fd < 0) {
    printf("Passed Invalid File Descriptor.\n");
    return -1;
  }

  /* Null Buffer */
  if (buffer == NULL) {
    printf("Passed A Null Buffer.\n");
    return -1;
  }

  /* Write To STDOUT */
  if (fd == 1) {
    putbuf((char*)buffer, length);
    return (int) length;
  }

  /* Writing To File */
  printf("Writing to anything but STDOUT not yet implemented.\n");
  return -1;
}
