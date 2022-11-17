#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"
#include "kernel/hash.h"
#include "kernel/list.h"
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/file.h"

#define STDIN_FILENO 0
#define STDOUT_FILENO 1

/**
 *  TODO: Whenever a user process wants to access some kernel functinality,
 *        it invokes a system call. This is a skeleton system call handler.
 *        Currently, it just prints a message and terminates the user process.
 *        In the second part of this project you will add code to do everyting
 *        else needed by system calls.
 */
static void syscall_handler(struct intr_frame *);

unsigned int next_fd;
// struct lock file_lock;

void syscall_init(void)
{
  next_fd = 2;
  // lock_init(&cur->file_lock);
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
  // printf("--------------Entering syscall handler--------------");
  if (f == NULL)
  {
    printf("Invalid intr_frame\n");
    thread_exit();
  }

  void *esp = f->esp;
  // sanity check
  if (esp >= (void *)0xbffffffc)
  {
    exit(-1);
  }
  int *syscall_number = (int *)esp;
  esp += sizeof(*syscall_number);

  int *status;
  int *fd;
  void *buffer;
  int *length;
  pid_t *pid;

  switch (*syscall_number)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    status = (int *)esp;
    exit(*status);
    break;
  case SYS_EXEC:
    buffer = esp;
    esp += sizeof(buffer);
    f->eax = exec(buffer);
    break;
  case SYS_WAIT:;
    pid = (int *)esp;
    esp += sizeof(pid);
    f->eax = wait(*pid);
    break;
  case SYS_CREATE:
    buffer = esp;
    esp += sizeof(buffer);
    unsigned *int_size = (unsigned*) esp;
    esp += sizeof(int_size);
    f->eax = create(buffer, *int_size);
    break;
  case SYS_REMOVE:
    buffer = esp;
    esp += sizeof(buffer);
    f->eax = remove(buffer);
    break;
  case SYS_OPEN:
    buffer = esp;
    esp += sizeof(buffer);
    fd = (int*) open(buffer);
    f->eax = *fd;
    break;
  case SYS_FILESIZE:
    fd = (int *)esp;
    esp += sizeof(fd);
    f->eax = filesize(*fd);
    break;
  case SYS_READ:
    fd = (int *)esp;
    esp += sizeof(fd);
    buffer = esp;
    esp += sizeof(buffer);
    length = (int *)esp;
    esp += sizeof(length);
    f->eax = read(*fd, buffer, *length);
    break;
  case SYS_WRITE:
    fd = (int *)esp;
    esp += sizeof(fd);
    buffer = esp;
    esp += sizeof(buffer);
    length = (int *)esp;
    esp += sizeof(length);
    f->eax = write(*fd, buffer, *length);
    break;
  case SYS_SEEK:
    fd = (int *)esp;
    esp += sizeof(fd);
    unsigned *pos = (unsigned*) esp;
    esp += sizeof(pos);
    // f->eax = seek(*fd, *pos); seek has no return value
    seek(*fd, *pos);
    break;
  case SYS_TELL:
    fd = (int *)esp;
    esp += sizeof(fd);
    f->eax = tell(*fd);
    break;
  case SYS_CLOSE:
    fd = (int *)esp;
    esp += sizeof(fd);
    close(*fd);
    // f->eax = close(*fd); close has no return value
    break;
  default:
    printf("This System Call (%d) is not yet supported.\n", *syscall_number);
    thread_exit();
    break;
  }
  // printf("---------------Exiting Process Wait---------------\n");
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
  // printf("---------------Entering Syscall Exit---------------\n");
  /* Getting current thread */
  struct thread *cur = thread_current();
  // TODO: needs to exit the child thread instead of cur thread.
  // should be in process.
  printf("%s: exit(%d)\n", cur->name, status);
  cur->status = status;
  // printf("---------------Exiting Syscall Exit---------------\n");
  thread_exit();
}

pid_t exec(const char *cmd_line)
{
  // TODO
  ASSERT(thread_current()->status == THREAD_RUNNING);
  tid_t return_pid = process_execute(cmd_line);
  if (return_pid == -1) {
    return -1;
  }
  // Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable.
  return return_pid;
}

int wait(pid_t pid)
{
  // This is not working
  return process_wait(pid);
}

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
  if (strlen(file) > 14)
  {
    printf("NOT DONE YET: FILE NAME TOO LONG\n");
    thread_exit(); // FIX wym???
  }
  struct thread *cur = thread_current();
  lock_acquire(&cur->file_lock);
  bool status = filesys_create(file, initial_size);
  // Don't map here.
  lock_release(&cur->file_lock);
  return status;
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
  if (strlen(file) > 14)
  {
    printf("NOT DONE YET: FILE NAME TOO LONG\n");
    return false; // FIX wym???
  }
  struct thread *cur = thread_current();
  lock_acquire(&cur->file_lock);
  bool success = filesys_remove(file);
  if (success)
  {
    // TODO: needs to remove it from the list if successful.
    struct file_entry *fe = get_entry_by_name(file);
    list_remove(&fe->elem);
    free(fe);
  }
  lock_release(&cur->file_lock);
  return success;
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
  printf("---------------Entering Syscall Open---------------\n");
  struct thread *cur = thread_current();
  lock_acquire(&cur->file_lock);
  struct file *opened_file = filesys_open(file);
  if (opened_file == NULL)
  {
    printf("COULD NOT OPEN FILE: %s\n", file);
    lock_release(&cur->file_lock);
    return -1;
  }
  struct file_entry *entry = malloc(sizeof(struct file_entry));
  int cur_fd = next_fd;
  next_fd = next_fd + 1;
  entry->file = opened_file;
  memset(entry->file_name, 0, sizeof(file));
  strlcpy(entry->file_name, file, sizeof(file));
  entry->fd = cur_fd;
  struct list file_list = thread_current()->file_list;
  list_push_back(&file_list, &entry->elem);
  lock_release(&cur->file_lock);
  printf("---------------Exiting Syscall Open---------------\n");
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
  if (fd < 0)
    return -1;
  struct thread *cur = thread_current();
  lock_acquire(&cur->file_lock);
  struct file_entry *fe = get_entry_by_fd(fd);
  unsigned size = file_length(fe->file);
  lock_release(&cur->file_lock);
  return size;
}

int read(int fd, void *buffer, unsigned length UNUSED)
{
  // printf("made it to read\n");
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

  if (fd > 0)
  {
    struct file_entry *fe = get_entry_by_fd(fd);
    int bytes_read = file_read(fe->file, buffer, 0);
    return bytes_read;
  }

  /* Reading From File */
  // printf("Reading from anything but STDIN not yet implemented.\n");
  return -1;
}
int write(int fd, const void *buffer, unsigned length)
{
  // printf("made it to write\n");
  /* Invalid File Descriptor */
  if (fd < 0)
  {
    // printf("Passed Invalid File Descriptor.\n");
    return -1;
  }

  int *buff = (int *)buffer;

  /* Null Buffer */
  if (buff == NULL)
  {
    // printf("Passed A Null Buffer.\n");
    return -1;
  }

  /* Write To STDOUT */
  if (fd == 1)
  {
    putbuf((char *)*buff, length);
    return (int)length;
  }

  if (fd > 0)
  {
    struct file_entry *fe = get_entry_by_fd(fd);
    int bytes_write = file_write(fe->file, buffer, 0);
    return bytes_write;
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
  struct thread *cur = thread_current();
  lock_acquire(&cur->file_lock);
  struct file_entry *fe = get_entry_by_fd(fd);
  if (fe != NULL)
  {
    file_seek(fe->file, position);
  }
  lock_release(&cur->file_lock);
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
  struct thread *cur = thread_current();
  lock_acquire(&cur->file_lock);
  struct file_entry *fe = get_entry_by_fd(fd);
  if (fe == NULL)
    return 0;
  unsigned offset = file_tell(fe->file);
  lock_release(&cur->file_lock);
  return offset;
}

/**
 * @brief Closes file descriptor fd. Exiting or terminating a process
 *        implicitly closes all its open file descriptors, as if
 *        by calling this function for each one.
 * @param fd
 */
void close(int fd)
{
  struct thread *cur = thread_current();
  lock_acquire(&cur->file_lock);
  struct file_entry *fe = get_entry_by_fd(fd);
  if (fe != NULL)
  {
    file_close(fe->file);
    list_remove(&fe->elem);
    free(fe);
  }
  lock_release(&cur->file_lock);
}

/**
 * @brief Get the file_entry by fd object, NULL if doesn't exist.
 *
 * @param fd
 * @return struct file_entry*
 */
struct file_entry *get_entry_by_fd(int fd)
{
  struct list_elem *e;
  struct list *file_list = &thread_current()->file_list;
  e = list_head(file_list);
  for (e = list_begin(file_list); e != list_end(file_list);
       e = list_next(e))
  {
    struct file_entry *cur = list_entry(e, struct file_entry, elem);
    if (cur->fd == fd)
    {
      return cur;
    }
  }
  return NULL;
}

/**
 * @brief Get the file_entry by name, NULL if doesn't exist.
 *
 * @param name
 * @return struct file_entry*
 */
struct file_entry *get_entry_by_name(const char *name)
{
  struct list_elem *e;
  struct list *file_list = &thread_current()->file_list;
  e = list_head(file_list);
  for (e = list_begin(file_list); e != list_end(file_list);
       e = list_next(e))
  {
    struct file_entry *cur = list_entry(e, struct file_entry, elem);
    if (strcmp(cur->file_name, name))
    {
      return cur;
    }
  }
  return NULL;
}