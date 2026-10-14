// SPDX-License-Identifier: MIT
/* Native acceptance only: request Apple's completed snapshot revert through
 * the published XNU APFSIOC_REVERT_TO_SNAPSHOT interface. No APFS disk records
 * are constructed. The selected XID comes from diskutil's native inventory. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *actions = getenv("GITHUB_ACTIONS");
    const char *environment = getenv("RUNNER_ENVIRONMENT");
    if (!actions || strcmp(actions, "true") || !environment || strcmp(environment, "github-hosted")) {
        fprintf(stderr, "Snapshot control requires a disposable GitHub-hosted VM\n");
        return 1;
    }
    if (argc != 3) return 1;
    struct statfs volume;
    if (statfs(argv[1], &volume) || strcmp(volume.f_fstypename, "apfs")) return 1;
    char *end;
    errno = 0;
    uint64_t xid = strtoull(argv[2], &end, 10);
    if (errno || *end || !xid || argv[2][0] == '-') return 1;
    /* XNU bsd/vfs/vfs_syscalls.c defines the request as _IOW('J',1,u_int64_t).
     * The installed apfs.util sends zero and cannot select an inventory XID.
     * Keep the request and argument typed; do not infer a private ioctl layout. */
    if (fsctl(argv[1], _IOW('J', 1, uint64_t), &xid, 0)) {
        perror("APFSIOC_REVERT_TO_SNAPSHOT");
        return 1;
    }
    printf("{\"api\":\"APFSIOC_REVERT_TO_SNAPSHOT\",\"xid\":%llu,\"status\":0}\n", (unsigned long long)xid);
    return 0;
}
