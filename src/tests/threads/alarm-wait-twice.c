#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"

void
test_alarm_wait_twice (void) 
{
  msg("Sleeping for 100 ticks.");
  timer_sleep (100);
  msg("Woke up, sleeping again for 100 ticks.");
  timer_sleep (100);
  msg("Woke up again.");
}
