// SPDX-License-Identifier: MIT
/* Native acceptance only: observe the supported, name-based snapshot APIs.
 * A successful probe process reports the syscall's actual status and errno;
 * syscall refusal is never represented as successful snapshot mutation. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/snapshot.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *actions = getenv("GITHUB_ACTIONS");
    const char *environment = getenv("RUNNER_ENVIRONMENT");
    if (!actions || strcmp(actions, "true") || !environment || strcmp(environment, "github-hosted")) {
        fprintf(stderr, "Snapshot control requires a disposable GitHub-hosted VM\n");
        return 1;
    }
    if (argc != 4 && argc != 5) return 1;
    const char *operation = argv[1];
    if (strcmp(operation, "create") && strcmp(operation, "rename") && strcmp(operation, "revert")) return 1;
    if ((argc == 5) != !strcmp(operation, "rename")) return 1;
    int fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return 1;
    struct statfs volume;
    if (fstatfs(fd, &volume) || strcmp(volume.f_fstypename, "apfs")) {
        close(fd);
        return 1;
    }
    errno = 0;
    int status;
    if (!strcmp(operation, "create")) status = fs_snapshot_create(fd, argv[3], 0);
    else if (!strcmp(operation, "rename")) status = fs_snapshot_rename(fd, argv[3], argv[4], 0);
    else status = fs_snapshot_revert(fd, argv[3], 0);
    int failure = status ? errno : 0;
    close(fd);
    printf("{\"api\":\"fs_snapshot_%s\",\"status\":%d,\"errno\":%d}\n", operation, status, failure);
    return 0;
}
