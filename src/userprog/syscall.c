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
void halt(void);
void exit(int status);
// pid_t exec(const char *cmd_line);
// int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  /*
   * The system call number is in the 32-bit word at the caller's stack pointer.
   * The first argument is in the 32-bit word at the next higher address, and so on.
   * The caller's stack pointer is accessible by the esp member of *f.
   */
  if (f == NULL)
  {
    printf("Invalid intr_frame\n");
    thread_exit();
  }

  void *esp = f->esp;
  // sanity check
  if (esp >= 0xbffffffc)
  {
    exit(-1);
  }
  int syscall_number = *((int *)esp);
  esp += sizeof(syscall_number);

  int *status;
  int *fd;
  int *buffer;
  int *length;

  switch (syscall_number)
  {
  case SYS_EXIT:
    status = (int *)esp;
    exit(*status);
    break;
  case SYS_READ:
    fd = (int *)esp;
    esp += sizeof(fd);
    buffer = (int *)esp;
    esp += sizeof(buffer);
    length = (int *)esp;
    esp += sizeof(length);
    f->eax = read(*fd, *buffer, *length);
    break;
  case SYS_WRITE:
    fd = (int *)esp;
    esp += sizeof(fd);
    buffer = (int *)esp;
    esp += sizeof(buffer);
    length = (int *)esp;
    esp += sizeof(length);
    f->eax = write(*fd, *buffer, *length);
    break;
  default:
    printf("This System Call (%d) is not yet supported.\n", syscall_number);
    thread_exit();
    break;
  }
}

/**
 * @brief Terminates Pintos by calling shutdown_power_off() 
 *        (declared in devices/shutdown.h). This should be seldom 
 *        used, because you lose some information about possible 
 *        deadlock situations, etc.
 */
void halt(void)
{
  // TODO
  return;
}

void exit(int status)
{
  /* Getting current thread */
  struct thread *cur = thread_current();
  // should be in process.
  printf("%s: exit(%d)\n", cur->name, status);
  // cur->status = status;

  thread_exit();
}

// pid_t exec(const char *cmd_line)
// {
//   // TODO
//   return -1;
// }

// int wait(pid_t pid)
// {
//   // TODO
//   return -1;
// }

/**
 * @brief Creates a new file called file initially initial_size
 *        bytes in size. Returns true if successful, false otherwise.
 *        Creating a new file does not open it: opening the new file 
 *        is a separate operation which would require a open system call.
 * 
 * @param file 
 * @param initial_size 
 * @return true 
 * @return false 
 */
bool create(const char *file, unsigned initial_size)
{
  // TODO
  return false;
}

/**
 * @brief Deletes the file called file. Returns true if successful, 
 *        false otherwise. A file may be removed regardless of whether 
 *        it is open or closed, and removing an open file does not close it.
 * 
 * @param file 
 * @return true 
 * @return false 
 */
bool remove(const char *file)
{
  // TODO
  return false;
}

/**
 * @brief Opens the file called file. Returns a nonnegative integer
 *        handle called a "file descriptor" (fd), or -1 if the file 
 *        could not be opened.
 * 
 * @param file 
 * @return int 
 */
int open(const char *file)
{
  // TODO
  return -1;
}

/**
 * @brief Returns the size, in bytes, of the file open as fd.
 * 
 * @param fd 
 * @return int 
 */
int filesize(int fd)
{
  // TODO
  return -1;
}

int read(int fd, void *buffer, unsigned length UNUSED)
{
  /* Invalid File Descriptor */
  if (fd < 0)
  {
    // printf("Passed Invalid File Descriptor.\n");
    return -1;
  }

  /* Null Buffer */
  if (buffer == NULL)
  {
    // printf("Passed A Null Buffer.\n");
    return -1;
  }

  /* Reading From Keyboard */
  if (fd == 0)
  {
    return input_getc();
  }

  /* Reading From File */
  // printf("Reading from anything but STDIN not yet implemented.\n");
  return -1;
}
int write(int fd, const void *buffer, unsigned length)
{
  /* Invalid File Descriptor */
  if (fd < 0)
  {
    // printf("Passed Invalid File Descriptor.\n");
    return -1;
  }

  uint8_t *buff = (uint8_t *)buffer;

  /* Null Buffer */
  if (buff == NULL)
  {
    // printf("Passed A Null Buffer.\n");
    return -1;
  }

  /* Write To STDOUT */
  if (fd == 1)
  {
    putbuf((char *)buff, length);
    return (int)length;
  }

  /* Writing To File */
  // printf("Writing to anything but STDOUT not yet implemented.\n");
  return -1;
}

/**
 * @brief Changes the next byte to be read or written in open 
 *        file fd to position, expressed in bytes from the beginning 
 *        of the file. (Thus, a position of 0 is the file's start.)
 * 
 * @param fd 
 * @param position 
 */
void seek(int fd, unsigned position)
{
  // TODO
  return;
}

/**
 * @brief Returns the position of the next byte to be read or 
 *        written in open file fd, expressed in bytes from the 
 *        beginning of the file.
 * @param fd 
 * @return unsigned 
 */
unsigned tell(int fd)
{
  // TODO
  return 0;
}

/**
 * @brief Closes file descriptor fd. Exiting or terminating a process 
 *        implicitly closes all its open file descriptors, as if 
 *        by calling this function for each one.
 * @param fd 
 */
void close(int fd)
{
  // TODO
  return;
}
