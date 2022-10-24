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
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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

  void *esp = f->esp;
  // sanity check
  if (esp >= 0xbffffffc)
  {
    exit(-1);
  }
  int *syscall_number = (int*) esp;
  esp += sizeof(*syscall_number);

  int *status;
  int *fd;
  void *buffer;
  int *length;

  switch (*syscall_number) {
    case SYS_EXIT:
      status = (int*) esp;
      exit(*status);
      break;
    case SYS_READ:
      fd = (int*) esp;
      esp += sizeof(fd);
      buffer = esp;
      esp += sizeof(buffer);
      length = (int*) esp;
      esp += sizeof(length);
      f->eax = read(*fd, buffer, *length);
      break;
    case SYS_WRITE:
      fd = (int*) esp;
      esp += sizeof(fd);
      buffer = esp;
      esp += sizeof(buffer);
      length = (int*) esp;
      esp += sizeof(length);
      f->eax = write(*fd, buffer, *length);
      break;
    default:
      printf("This System Call (%d) is not yet supported.\n", *syscall_number);
      thread_exit();
      break;
  }
}

void
exit (int status)
{
  /* Getting current thread */
  struct thread *cur = thread_current();
  // should be in process.
  printf("%s: exit(%d)\n", cur->name, status);
  // cur->status = status;

  thread_exit();
}

int
read (int fd, void *buffer, unsigned length UNUSED)
{
  /* Invalid File Descriptor */
  if (fd < 0) {
    // printf("Passed Invalid File Descriptor.\n");
    return -1;
  }

  /* Null Buffer */

  if (buffer == NULL) {
    // printf("Passed A Null Buffer.\n");
    return -1;
  }

  /* Reading From Keyboard */
  if (fd == 0) {
    return input_getc();
  }

  /* Reading From File */
  // printf("Reading from anything but STDIN not yet implemented.\n");
  return -1;
}
int
write (int fd, const void *buffer, unsigned length)
{
  /* Invalid File Descriptor */
  if (fd < 0) {
    // printf("Passed Invalid File Descriptor.\n");
    return -1;
  }

  int *buff = (int*) buffer;

  /* Null Buffer */
  if (buff == NULL) {
    // printf("Passed A Null Buffer.\n");
    return -1;
  }

  /* Write To STDOUT */
  if (fd == 1) {
    putbuf((char*) *buff, length);
    return (int) length;
  }

  /* Writing To File */
  // printf("Writing to anything but STDOUT not yet implemented.\n");
  return -1;
}
