                      +-----------------+
                     	|  	CS 450 	|
                     	|  SAMPLE PROJECT |
                     	| DESIGN DOCUMENT |
                     	+-----------------+
 
---- GROUP ----
 

Patrick Glebus glebuspm@dukes.jmu.edu
Ernie Tussey tusseyel@dukes.jmu.edu
Jacob Lewis lewisjw@dukes.jmu.edu
Andrew Fryer fryerak@dukes.jmu.edu
 

 
 
---- PRELIMINARIES ----
 
>> If you have any preliminary comments on your submission or notes for
>> me, please give them here.
 
None.
 
>> Please cite any offline or online sources you consulted while
>> preparing your submission, other than the Pintos documentation,
>> course text, and lecture notes.
 
None.
 
            	                 PRIORITY SCHEDULING
                         ===================

---- DATA STRUCTURES ----

>> B1: Copy here the declaration of each new or changed `struct' or
>> `struct' member, global or static variable, `typedef', or
>> enumeration.  Identify the purpose of each in 25 words or less.

		sync.h
1. struct semaphore
    	unsigned value;             /* Current value. */
    	struct list waiters;        /* List of waiting threads. */
    	int prio;                   /* Prio of its current thread */
2. struct lock 
struct thread *holder;      /* Thread holding lock (for debugging). */
struct semaphore semaphore; /* Binary semaphore controlling access. */
struct list waiters;
int priority;

Thread.h new stuff
Thread struct
Struct list_elem lock_list /* a list of stuff waiting on the cur thread  sorted by priority */
struct list_elem lock_elem; /* representation of the waiter in list*/
Struct lock* waiting_on /* the lock the cur thread is waiting on*/
Int priority changed to int initial_priority;
Int priority /* the donated priority*/

>> B2: Explain the data structure used to track priority donation.

Our main data structure is a field in thread that designates the current holder of the lock. 
Through a chain of holders, we are able to determine how to designate the highest priority efficiently
to the ‘prime’ holder of the lock. The holder also has a designated lock_list of threads waiting on it to
finish its possession of the lock. This list is used to determine what thread should be yielded too based
on the next highest effective priority.

---- ALGORITHMS ----

>> B3: How do you ensure that the highest priority thread waiting for
>> a lock, semaphore, or condition variable wakes up first?

For locks we priority sort their lists, and then designate the scheduler to wake up the highest priority
thread based off of our chain of donations.
For semaphores we designate a priority to its waiters list, that is sorted before the front element is
popped.
For condition we sort the semaphore_elem in the condition variable’s waiters list. 

>> B4: Describe the sequence of events when a call to lock_acquire()
>> causes a priority donation.  How is nested donation handled?

Lock acquire gets the current thread for use later in the function, then it sees if the lock has a
non-null holder - if not it continues normally since it’s the first to acquire it. Otherwise if the current lock
has a holder, the current thread that wants it is put into its holder list. While the holder is not null, we check
to see if the current->priority needs to be donated to the lock’s holder it wants to obtain. We then look to see if
the lock’s holder is also waiting on other locks, then update and repeat those. During this process, interrupts are
disabled in order to provide pseudo-synchronization in a way that lists and priorities aren’t affected through
multiple acquire attempts.

>> B5: Describe the sequence of events when lock_release() is called
>> on a lock that a higher-priority thread is waiting for.

The lock holder is set to NULL, in order to allow another thread to grab possession of it. We then update the list of
threads that are waiting on the current thread by letting them know the lock is up for grabs for the highest priority
thread, then clear up the lock list. We then reset the current thread's effective priority back to its initial priority,
and yield if necessary. Interrupts are not disabled during this process, as each thread is only affecting its own lock
list when it is releasing thread dependencies and it is not changing other threads' effective priorities..

---- SYNCHRONIZATION ----

>> B6: Describe a potential race in thread_set_priority() and explain
>> how your implementation avoids it.  Can you use a lock to avoid
>> this race?

A potential race condition is that if we have two threads try to update a threads priority at the same time.
To enforce this, we have disabled interrupts before this function is used in the sync.c file.


---- RATIONALE ----

>> B7: Why did you choose this design?  In what ways is it superior to
>> another design you considered?

We decided it would be easier to have a list of waiting threads to easily determine and relinquish which
threads need which locks through the donation chain. We tried some other implementations in which threads
had knowledge of the priority recipients, but this felt like unnecessary information. We landed on this design,
because we felt it was overall relatively simple with few changes - but also provided much flexibility.
Also we had a hard time with chaining priority donations to threads that currently held locks with earlier
implementations, especially maintaining list to provide this, with our current design for lock_aquire it was
a lot easier to determine what was the next dependency that needed to be properly donated to.

We also tried to have the lock to know what the next highest priority thing it needed to assign itself to was.
However this was a pain to try and implement and we never got it off the ground.

We also initially tried to thread yield when a thread was created, however this would stop highest priority
processes from running mid execution on every thread created. However, we did change this so that when a thread
is created it is unblocked, and in unblock it determines if the current thread is the highest priority thing and
if not it yields to whatever is.



