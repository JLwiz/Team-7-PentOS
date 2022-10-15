#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void exit (int status);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void syscall_init (void);


#endif /* userprog/syscall.h */
