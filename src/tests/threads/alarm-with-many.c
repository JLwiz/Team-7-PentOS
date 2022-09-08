#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"

#define NUM_THREADS 10

static void sleeper (void *);
// 
/* Information about the test. */
struct sleep_test 
  {
    int64_t start;          /* Current time before thread sleeps. */
    int64_t end;            /* Current time after thread wakes up */
  };

void
test_alarm_with_many (void) 
{

  struct sleep_test test;

  msg ("Creating a thread to sleep 100 ticks.");
  msg ("The thread will return the ticks in which it slept and ran again.");

  /* Start thread. */

  thread_create ("thread 0", PRI_DEFAULT, sleeper, &test);

  /* Wait long enough for the thread to finish. */
  timer_sleep (300);

  msg("Test started at clock time %d", test.start);
  msg("Thread resumed at clock time %d", test.end);

}

/* Sleeper thread. */
static void
sleeper (void *test_) 
{
  struct sleep_test *test = test_;

  test->start = timer_ticks();
  timer_sleep(100);
  test->end = timer_ticks();

}
