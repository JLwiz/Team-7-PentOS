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
  f->esp += 4;

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
  intr_dump_frame(f);
  int arg0 = *((int*)args);
  args += 4;
  int arg1 = *((int*)(args));
  args += 4;
  int arg2 = *((int*)(args));
  args += 4;

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

  printf("Entering systemcall \n");
  hex_dump(f->esp, f->esp, 64, true);
  intr_dump_frame(f);
  /*
   * The system call number is in the 32-bit word at the caller's stack pointer.
   * The first argument is in the 32-bit word at the next higher address, and so on.
   * The caller's stack pointer is accessible by the esp member of *f.
  */
  if (f == NULL) {
    printf("Invalid intr_frame\n");
    thread_exit();
  }

  printf("Syscall Stack Pointer: %p\n", f->esp);

  hex_dump(f->esp, f->esp, 512, true);

  int syscall_number = *((int*)f->esp);
  void *args = f->esp += 4;
  printf("Syscall Stack Pointer: %p\n", f->esp);

    
  switch (syscall_number) {
    case SYS_EXIT:
      printf("Exit\n");
      syscall_1(f, SYS_EXIT, args);
      break;
    case SYS_READ:
      printf("Read\n");
      syscall_3(f, SYS_READ, args);
      break;
    case SYS_WRITE:
      printf("Write\n");
      syscall_3(f, SYS_WRITE, args);
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
  printf("%s: exit(%d)\n", cur->name, status);
  cur->status = status;

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

  uint8_t *buff = (uint8_t*) buffer;

  /* Null Buffer */
  if (buff == NULL) {
    printf("Passed A Null Buffer.\n");
    return -1;
  }

  /* Write To STDOUT */
  if (fd == 1) {
    putbuf((char*)buff, length);
    printf("\n");
    return (int) length;
  }

  /* Writing To File */
  printf("Writing to anything but STDOUT not yet implemented.\n");
  return -1;
}
