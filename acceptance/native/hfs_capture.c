/* Native acceptance only. Pause the helper owning one disposable HFS image
 * after a journal-end update, retain its backing bytes, and always resume it.
 * No filesystem bytes, cursors or transactions are manufactured here. */
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopped_pid;
static void interrupted(int signal_number) {
    if (stopped_pid) kill(stopped_pid, SIGCONT);
    _exit(128 + signal_number);
}
static uint64_t little64(const unsigned char *data) {
    uint64_t value = 0;
    for (int i = 7; i >= 0; i--) value = value * 256 + data[i];
    return value;
}
static double now(void) {
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return time.tv_sec + time.tv_nsec / 1e9;
}
int main(int argc, char **argv) {
    const char *actions = getenv("GITHUB_ACTIONS");
    const char *environment = getenv("RUNNER_ENVIRONMENT");
    if (!actions || strcmp(actions, "true") || !environment || strcmp(environment, "github-hosted")) {
        fprintf(stderr, "Capture requires a disposable GitHub-hosted VM\n"); return 1;
    }
    if (argc != 5) return 1;
    char *last;
    long identifier = strtol(argv[2], &last, 10);
    if (*last || identifier <= 1 || identifier > INT32_MAX) return 1;
    pid_t helper = (pid_t)identifier;
    char executable[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(helper, executable, sizeof(executable)) <= 0 ||
        (!strstr(executable, "diskimages-helper") && !strstr(executable, "diskimagesiod"))) {
        fprintf(stderr, "Not an image helper\n"); return 1;
    }
    off_t header = (off_t)strtoll(argv[3], &last, 10);
    if (*last || header <= 0) return 1;
    int input = open(argv[1], O_RDONLY);
    struct stat size;
    if (input < 0 || fstat(input, &size) || !S_ISREG(size.st_mode) || size.st_size != (64 << 20)) return 1;
    if (fcntl(input, F_NOCACHE, 1)) { perror("F_NOCACHE"); return 1; }
    unsigned char state[48];
    if (pread(input, state, sizeof(state), header) != sizeof(state) || memcmp(state, "xLNJ", 4)) return 1;
    uint64_t original_end = little64(state + 16);
    fprintf(stderr, "Watch journal: start=%llu end=%llu\n", (unsigned long long)little64(state + 8), (unsigned long long)original_end);
    double deadline = now() + 15;
    while (now() < deadline) {
        if (pread(input, state, sizeof(state), header) != sizeof(state)) return 1;
        if (little64(state + 8) != little64(state + 16) && little64(state + 16) != original_end) break;
    }
    if (now() >= deadline) { fprintf(stderr, "No new pending journal commit: last start=%llu end=%llu\n", (unsigned long long)little64(state+8), (unsigned long long)little64(state+16)); return 1; }
    signal(SIGINT, interrupted); signal(SIGTERM, interrupted); signal(SIGHUP, interrupted);
    // An independent watchdog resumes the helper even if this process dies.
    pid_t watchdog = fork();
    if (watchdog < 0) return 1;
    if (watchdog == 0) { sleep(2); kill(helper, SIGCONT); _exit(0); }
    stopped_pid = helper;
    int failed = kill(helper, SIGSTOP) != 0;
    int output = failed ? -1 : open(argv[4], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (output < 0) failed = 1;
    unsigned char buffer[128 << 10];
    for (off_t offset = 0; !failed && offset < size.st_size; offset += sizeof(buffer)) {
        ssize_t count = pread(input, buffer, sizeof(buffer), offset);
        if (count != sizeof(buffer) || write(output, buffer, sizeof(buffer)) != sizeof(buffer)) failed = 1;
    }
    kill(helper, SIGCONT); stopped_pid = 0;
    kill(watchdog, SIGTERM); waitpid(watchdog, NULL, 0);
    if (output >= 0 && close(output)) failed = 1;
    close(input);
    if (failed) { unlink(argv[4]); perror("capture"); }
    else printf("Captured helper %d after end=%llu\n", helper, (unsigned long long)little64(state + 16));
    return failed;
}
