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
#include "threads/vaddr.h"
#include <limits.h>
#include "userprog/pagedir.h"

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
bool check_if_file_exists_by_fd(int fd);
// unsigned int next_fd;
// struct lock file_lock;

void syscall_init(void)
{
  // next_fd = 2;
  // lock_init(&cur->file_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

 	
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  if (!is_user_vaddr(uaddr)) return -1;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

static void validate_pointer(void *p)
{
  if (get_user(p) == -1)
    {
      exit(-1);
    }
    
}


/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
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
  validate_pointer(esp);
  // sanity check
  if (esp >= (void *)0xbffffffc && esp <= PHYS_BASE)
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
  int test_pid;
  char *filename;

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
    buffer = *(char**)esp;
    esp += sizeof(buffer);
    validate_pointer(esp);
    f->eax = exec(buffer);
    break;
  case SYS_WAIT:;
    test_pid = *(int *)esp;
    esp += sizeof(pid);
    validate_pointer(esp);
    f->eax = wait(test_pid);
    break;
  case SYS_CREATE:
    filename = *(char**) esp;
    esp += sizeof(filename);
    validate_pointer(esp);
    unsigned *int_size = (unsigned*) esp;
    esp += sizeof(int_size);
    validate_pointer(esp);
    f->eax = create(filename, *int_size);
    break;
  case SYS_REMOVE:
    filename = *(char**) esp;
    esp += sizeof(filename);
    validate_pointer(esp);
    f->eax = remove(filename);
    break;
  case SYS_OPEN:
    filename = *(char**) esp;
    esp += sizeof(filename);
    validate_pointer(esp);
    f->eax = open(filename);
    break;
  case SYS_FILESIZE:
    fd = (int *)esp;
    esp += sizeof(fd);
    validate_pointer(esp);
    f->eax = filesize(*fd);
    break;
  case SYS_READ:
    // printf("ENTERING READ\n");
    fd = (int *)esp;
    esp += sizeof(fd);
    validate_pointer(esp);
    buffer = esp;
    esp += sizeof(buffer);
    validate_pointer(esp);
    length = (int *)esp;
    esp += sizeof(length);
    validate_pointer(esp);
    f->eax = read(*fd, buffer, *length);
    // printf("EXITING READ\n");
    break;
  case SYS_WRITE:
    fd = (int *)esp;
    esp += sizeof(fd);
    validate_pointer(esp);
    buffer = *(char**) esp;
    esp += sizeof(buffer);
    validate_pointer(esp);
    length = (int *)esp;
    esp += sizeof(length);
    validate_pointer(esp);
    f->eax = write(*fd, (void*)buffer, *length);
    break;
  case SYS_SEEK:
    fd = (int *)esp;
    esp += sizeof(fd);
    validate_pointer(esp);
    unsigned *pos = (unsigned*) esp;
    esp += sizeof(pos);
    validate_pointer(esp);
    // f->eax = seek(*fd, *pos); seek has no return value
    seek(*fd, *pos);
    break;
  case SYS_TELL:
    fd = (int *)esp;
    esp += sizeof(fd);
    validate_pointer(esp);
    f->eax = tell(*fd);
    break;
  case SYS_CLOSE:
    fd = (int *)esp;
    esp += sizeof(fd);
    validate_pointer(esp);
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
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  cur->exit_status = status;
  thread_exit();
}

pid_t exec(const char *cmd_line)
{
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
  int status = process_wait( (tid_t) pid);
  return status;
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
  if (file == NULL)
  {
    exit(-1);
  }
  validate_pointer((void *)file);
  if (strlen(file) > 14 || sizeof(file) > 14)
    return 0;

  get_file_lock();
  bool status = filesys_create(file, initial_size);
  release_file_lock();
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
  validate_pointer((void *)file);
  if (strlen(file) > 14)
  {
    return false;
  }
  get_file_lock();
  bool success = filesys_remove(file);
  release_file_lock();
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

  // printf("---------------Entering Syscall Open---------------\n");
  if (file == NULL) exit(-1);

  validate_pointer((void *)file);
  struct thread *cur = thread_current();
  get_file_lock();
  struct file *opened_file = filesys_open(file);
  if (opened_file == NULL)
  {
    release_file_lock();
    return -1;
  }

  struct file_entry *entry = malloc(sizeof(struct file_entry));
  int cur_fd = cur->next_fd;
  cur->next_fd = cur_fd + 1;
  entry->file = opened_file;
  entry->file_name = (char*) file;
  entry->fd = cur_fd;
  struct list file_list = thread_current()->file_list;
  list_push_back(&file_list, &entry->elem);
  release_file_lock();
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
  get_file_lock();
  struct file_entry *fe = get_entry_by_fd(fd);
  unsigned size = file_length(fe->file);
  release_file_lock();
  return size;
}

int read(int fd, void *buffer, unsigned length)
{
  validate_pointer(buffer);

  if(is_kernel_vaddr(*(char**)buffer)) exit(-1);
  if (fd < 0)
  {
    return -1;
  }

  /* Null Buffer */
  if (buffer == NULL)
  {
    return -1;
  }
  
  /* Reading From Keyboard */
  if (fd == 0)
  {
    printf("Reading from keyboard \n");
    size_t i = 0;
    for (i = 0; i < length; i++)
    {
      *(uint8_t *)(buffer + i) = input_getc();
    }
    return i;
  }
  // Should probably get the fe once its opened.
  /* Reading From File */
  if (fd > 0)
  {
    if (length == 0) return 0;
    get_file_lock();
    struct file_entry *fe = get_entry_by_fd(fd);
    if (fe == NULL) {
      release_file_lock();
      return -1;
    }

    struct file *file = fe->file;
    if (file == NULL) {
      release_file_lock();
      return -1;
    }
    int bytes_read = file_read(file, *(char **)buffer, length);
    release_file_lock();
    return bytes_read;
  }
  return -1;
}
int write(int fd, const void *buffer, unsigned length)
{ 
  /* Invalid File Descriptor */
  if (fd < 0)
  {
    return -1;
  }

  validate_pointer((void *)buffer);

  validate_pointer(((void *)buffer) + length);

  /* Null Buffer */
  if (buffer == NULL)
  {
    return -1;
  }
  /* Write To STDOUT */
  if (fd == 1)
  {
    putbuf( (char*) buffer, length);
    return (int)length;
  }

  /* Writing To File */
  if (fd > 0)
  {
    get_file_lock();
    struct file_entry *fe = get_entry_by_fd(fd);
    if (fe == NULL)
    {
      release_file_lock();
      return -1;
    }
    if (fe->file == NULL) 
    {
      release_file_lock();
      return -1;
      }
    int bytes_write = file_write(fe->file, buffer, length);
    release_file_lock();
    return bytes_write;
  }
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
  get_file_lock();
  struct file_entry *fe = get_entry_by_fd(fd);
  if (fe != NULL)
  {
    file_seek(fe->file, position);
  }
  release_file_lock();
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
  get_file_lock();
  struct file_entry *fe = get_entry_by_fd(fd);
  if (fe == NULL)
    return 0;
  unsigned offset = file_tell(fe->file);
  release_file_lock();
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
  get_file_lock();
  struct file_entry *fe = get_entry_by_fd(fd);
  if (fe != NULL)
  {
    file_close(fe->file);
    list_remove(&fe->elem);
    free(fe);
  }
  release_file_lock();
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

