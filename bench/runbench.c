// Wall-clock of a command from spawn to exit, without shell or `date` overhead (which add ~1.5 ms,
// more than fastsigner itself takes on a small APK).
//
//   gcc -O2 -o runbench bench/runbench.c
//   runbench RUNS program args...      (program is a path; stdout/stderr go to /dev/null)
//
// Prints min / p25 / median / mean in ms; exits 1 if any run fails. SHOWERR=1 keeps stderr.
#define _GNU_SOURCE
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>

extern char **environ;

static int cmp(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return x < y ? -1 : x > y;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: runbench RUNS program [args...]\n");
    return 2;
  }
  int runs = atoi(argv[1]);
  if (runs < 1) runs = 1;
  double *t = malloc(sizeof(double) * runs), sum = 0;
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
  if (!getenv("SHOWERR")) posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
  for (int i = 0; i < runs; i++) {
    struct timespec a, b;
    pid_t pid;
    int st;
    clock_gettime(CLOCK_MONOTONIC, &a);
    if (posix_spawn(&pid, argv[2], &fa, NULL, argv + 2, environ)) {
      perror(argv[2]);
      return 2;
    }
    waitpid(pid, &st, 0);
    clock_gettime(CLOCK_MONOTONIC, &b);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) {
      fprintf(stderr, "run %d failed (status %d)\n", i, st);
      return 1;
    }
    t[i] = (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6;
    sum += t[i];
  }
  qsort(t, runs, sizeof(double), cmp);
  printf("min %.2f  p25 %.2f  median %.2f  mean %.2f ms\n", t[0], t[runs / 4], t[runs / 2], sum / runs);
  return 0;
}
