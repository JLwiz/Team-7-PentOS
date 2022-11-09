#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>

void halt(void);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
void exit (int status);
int open(const char *file);
int filesize(int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void syscall_init (void);
struct file_entry* get_entry_by_fd(int fd);


#endif /* userprog/syscall.h */
