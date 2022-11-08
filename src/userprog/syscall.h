#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>

// struct file_entry 
// {
//     unsigned int fd;
//     const char *file_name;
//     struct list_elem allelem;
//     struct list_elem elem;
// };

void exit (int status);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void syscall_init (void);


#endif /* userprog/syscall.h */
