#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"

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

unsigned int next_fd;
static struct list file_list;
struct semaphore file_list_semaphore;

void syscall_init(void)
{
  next_fd = 0;
  list_init(&file_list);
  sema_init(&file_list_semaphore, 1);
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
  if (esp >= (void*) 0xbffffffc)
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
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      status = (int*) esp;
      exit(*status);
      break;
    case SYS_EXEC:
      break;
    case SYS_WAIT:
      break;
    case SYS_CREATE:
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
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
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
    default:
      printf("This System Call (%d) is not yet supported.\n", *syscall_number);
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
  shutdown_power_off();
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
  bool success = filesys_create(file, initial_size);
  unsigned int cur_fd = next_fd;
  // add to file table
  if (success)
  {
    // someone double check this :)
    sema_down(&file_list_semaphore);
    struct file_entry *entry = malloc(sizeof(struct file_entry));
    entry->fd = cur_fd;
    entry->file_name = file;
    list_push_back(&file_list, &entry->elem);
    sema_up(&file_list_semaphore);
  }
  next_fd = next_fd + 1;
  return success;
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
  // needs to be passed an inode?
  // needs to be tested to see if this works.
  struct file *opened_file = filesys_open(file);
  if (opened_file == NULL) return -1;
  // TODO needs to place it within the list.
  unsigned int cur_fd = next_fd;
  next_fd++;
  return cur_fd;
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
  if (fd < 0) return -1;
  // struct file *file = get_file(fd);
  return ;
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

  if (buffer == NULL) {
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

  int *buff = (int*) buffer;

  /* Null Buffer */
  if (buff == NULL)
  {
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

