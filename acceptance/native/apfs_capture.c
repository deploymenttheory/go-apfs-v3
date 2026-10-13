// SPDX-License-Identifier: MIT
/* Native acceptance only. Observe Apple checkpoint writes in one runner-owned
 * image, pause that image's helper, retain the backing bytes, then resume it.
 * No APFS records, checksums or transaction identifiers are written. */
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
static void interrupted(int number) {
    if (stopped_pid) kill(stopped_pid, SIGCONT);
    _exit(128 + number);
}
static uint64_t little64(const unsigned char *p) {
    uint64_t result = 0;
    for (int i = 7; i >= 0; i--) result = result * 256 + p[i];
    return result;
}
static uint32_t little32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static int valid(const unsigned char *p, size_t size) {
    uint64_t a = 0, b = 0, mod = UINT32_MAX;
    for (size_t i = 8; i < size; i += 4) {
        a = (a + little32(p + i)) % mod;
        b = (b + a) % mod;
    }
    uint64_t x = mod - (a + b) % mod, y = mod - (a + x) % mod;
    return little64(p) == ((y << 32) | x);
}
static double now(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec + value.tv_nsec / 1e9;
}
static int latest(int input, uint64_t base, uint32_t count, unsigned char *selected) {
    unsigned char block[4096];
    uint64_t xid = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (pread(input, block, sizeof(block), (base + i) * sizeof(block)) != sizeof(block)) return -1;
        if (!memcmp(block + 32, "NXSB", 4) && valid(block, sizeof(block)) && little64(block + 16) > xid) {
            xid = little64(block + 16);
            memcpy(selected, block, sizeof(block));
        }
    }
    return xid ? 0 : -1;
}
int main(int argc, char **argv) {
    const char *actions = getenv("GITHUB_ACTIONS"), *environment = getenv("RUNNER_ENVIRONMENT");
    if (!actions || strcmp(actions, "true") || !environment || strcmp(environment, "github-hosted")) {
        fprintf(stderr, "Capture requires a disposable GitHub-hosted VM\n"); return 1;
    }
    if (argc != 5 || (strcmp(argv[4], "data") && strcmp(argv[4], "mapping") && strcmp(argv[4], "committed") && strcmp(argv[4], "wrapped"))) return 1;
    char *last;
    long identifier = strtol(argv[2], &last, 10);
    if (*last || identifier <= 1 || identifier > INT32_MAX) return 1;
    pid_t helper = (pid_t)identifier;
    char executable[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(helper, executable, sizeof(executable)) <= 0 ||
        (!strstr(executable, "diskimages-helper") && !strstr(executable, "diskimagesiod"))) return 1;
    int input = open(argv[1], O_RDONLY);
    struct stat info;
    if (input < 0 || fstat(input, &info) || !S_ISREG(info.st_mode) || info.st_size != (128 << 20)) return 1;
    if (fcntl(input, F_NOCACHE, 1)) return 1;
    unsigned char selected[4096], block[4096];
    if (pread(input, selected, sizeof(selected), 0) != sizeof(selected) || memcmp(selected + 32, "NXSB", 4) || !valid(selected, sizeof(selected))) return 1;
    uint64_t base = little64(selected + 112);
    uint32_t count = little32(selected + 104);
    if (!count || count > 256 || base > (uint64_t)info.st_size / 4096 - count || latest(input, base, count, selected)) return 1;
    uint64_t original = little64(selected + 16), previous = original;
    uint32_t previous_index = little32(selected + 144);
    int found = 0;
    double deadline = now() + 20;
    while (now() < deadline) {
        if (latest(input, base, count, selected)) return 1;
        uint64_t xid = little64(selected + 16);
        if (!strcmp(argv[4], "committed") && xid > original) { found = 1; break; }
        uint32_t index = little32(selected + 144);
        if (!strcmp(argv[4], "wrapped") && xid > previous && index < previous_index) { found = 1; break; }
        if (!strcmp(argv[4], "data") || !strcmp(argv[4], "mapping")) {
            uint64_t address = !strcmp(argv[4], "data") ? little64(selected + 120) + little32(selected + 132) : base + little32(selected + 128);
            if (address >= (uint64_t)info.st_size / 4096 || pread(input, block, sizeof(block), address * 4096) != sizeof(block)) return 1;
            if (little64(block + 16) > xid && valid(block, sizeof(block))) { found = 1; break; }
        }
        previous = xid; previous_index = index;
    }
    if (!found) { fprintf(stderr, "No checkpoint write window: mode=%s xid=%llu\n", argv[4], (unsigned long long)little64(selected + 16)); return 1; }
    signal(SIGINT, interrupted); signal(SIGTERM, interrupted); signal(SIGHUP, interrupted);
    pid_t watchdog = fork();
    if (watchdog < 0) return 1;
    if (!watchdog) { sleep(3); kill(helper, SIGCONT); _exit(0); }
    stopped_pid = helper;
    int failed = kill(helper, SIGSTOP) != 0;
    int output = failed ? -1 : open(argv[3], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (output < 0) failed = 1;
    if (!failed && fchown(output, info.st_uid, info.st_gid)) failed = 1;
    unsigned char buffer[128 << 10];
    for (off_t offset = 0; !failed && offset < info.st_size; offset += sizeof(buffer)) {
        if (pread(input, buffer, sizeof(buffer), offset) != sizeof(buffer) || write(output, buffer, sizeof(buffer)) != sizeof(buffer)) failed = 1;
    }
    kill(helper, SIGCONT); stopped_pid = 0;
    kill(watchdog, SIGTERM); waitpid(watchdog, NULL, 0);
    if (output >= 0 && close(output)) failed = 1;
    close(input);
    if (failed) unlink(argv[3]);
    else printf("{\"helper\":%d,\"mode\":\"%s\",\"observedXID\":%llu,\"initialXID\":%llu,\"previousDataIndex\":%u,\"observedDataIndex\":%u}\n", helper, argv[4], (unsigned long long)little64(selected + 16), (unsigned long long)original, previous_index, little32(selected + 144));
    return failed;
}
