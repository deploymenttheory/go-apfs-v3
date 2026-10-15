// SPDX-License-Identifier: MIT
/* Independent native storage observations. No APFS records are constructed.
 * Compile and invoke only on a disposable GitHub-hosted macOS VM. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *actions = getenv("GITHUB_ACTIONS");
    const char *environment = getenv("RUNNER_ENVIRONMENT");
    if (!actions || strcmp(actions, "true") || !environment || strcmp(environment, "github-hosted")) {
        fprintf(stderr, "Storage observation requires a disposable GitHub-hosted VM\n");
        return 1;
    }
    if (argc != 2) return 1;
    int fd = open(argv[1], O_RDONLY | O_NOFOLLOW);
    struct stat file;
    struct statfs volume;
    if (fd < 0 || fstat(fd, &file) || fstatfs(fd, &volume) ||
        !S_ISREG(file.st_mode) || strcmp(volume.f_fstypename, "apfs") ||
        file.st_size <= 0 || file.st_size > (4 << 20)) return 1;
    printf("{\"schema\":1,\"api\":\"F_LOG2PHYS_EXT\",\"object\":%llu,\"size\":%lld,\"ranges\":[",
           (unsigned long long)file.st_ino, (long long)file.st_size);
    off_t offset = 0;
    unsigned count = 0;
    while (offset < file.st_size) {
        struct log2phys mapping = {.l2p_contigbytes = file.st_size - offset, .l2p_devoffset = offset};
        if (++count > 4096 || fcntl(fd, F_LOG2PHYS_EXT, &mapping)) {
            perror("F_LOG2PHYS_EXT");
            close(fd);
            return 1;
        }
        if (mapping.l2p_devoffset < 0 || mapping.l2p_contigbytes <= 0) return 1;
        off_t length = mapping.l2p_contigbytes;
        if (length > file.st_size - offset) length = file.st_size - offset;
        printf("%s{\"logical\":%lld,\"physical\":%lld,\"length\":%lld,\"flags\":%u}",
               count > 1 ? "," : "", (long long)offset, (long long)mapping.l2p_devoffset,
               (long long)length, mapping.l2p_flags);
        offset += length;
    }
    puts("]}");
    return close(fd) ? 1 : 0;
}
