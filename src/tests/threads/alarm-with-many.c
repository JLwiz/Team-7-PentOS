/*

CS 450 Lab2
Fall 2022

Name: Jacob Lewis
Honor code statement: I did this inlign with class policy.

*/

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
  msg ("Creating a thread to sleep 100 ticks.");
  msg ("The thread will return the ticks in which it slept and ran again.");

  /* Start thread. */
  struct sleep_test *das_sleeper;
  das_sleeper = (struct sleep_test*)malloc(NUM_THREADS*sizeof(struct sleep_test));
  if (das_sleeper == NULL) {
    printf("Could not malloc %d threads for alarm-with-many test", NUM_THREADS);
    return;
  }
  for (int i = 0; i < NUM_THREADS; i++)
  {
    char *curr_thread = "thread " + i;
    thread_create (curr_thread, PRI_DEFAULT, sleeper, &das_sleeper[i]);
  }

  /* Wait long enough for the thread to finish. */
  timer_sleep (300);
  for (int i = 0; i < NUM_THREADS; i++)
  {    
    msg("thread %d", i);
    msg("\tTest started at clock time %d", das_sleeper[i].start);
    msg("\tThread resumed at clock time %d", das_sleeper[i].end);
  }
  free(das_sleeper);
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
