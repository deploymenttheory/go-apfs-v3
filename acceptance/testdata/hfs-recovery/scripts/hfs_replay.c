/* Native acceptance only: invoke Apple's replay-only HFS operation.
 * Its ABI is defined by hfs/hfs_mount.h and core/hfs_vfsops.c. This
 * program is never linked into Go or executed on a working Mac. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <hfs/hfs_mount.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *actions = getenv("GITHUB_ACTIONS");
    const char *environment = getenv("RUNNER_ENVIRONMENT");
    const char *disposable = getenv("APFS_NATIVE_DISPOSABLE_VM");
    if (!((actions && !strcmp(actions, "true") && environment && !strcmp(environment, "github-hosted")) ||
          (disposable && !strcmp(disposable, "1")))) {
        fprintf(stderr, "HFS replay requires a disposable macOS VM\n");
        return 1;
    }
    if (argc != 2 || strncmp(argv[1], "/dev/rdisk", 10)) return 1;
    struct vfsconf configuration;
    if (getvfsbyname("hfs", &configuration)) { perror("getvfsbyname"); return 1; }
    int descriptor = open(argv[1], O_RDWR);
    if (descriptor < 0) { perror("open"); return 1; }
    int mib[] = {CTL_VFS, configuration.vfc_typenum, HFS_REPLAY_JOURNAL, descriptor};
    int result = sysctl(mib, 4, NULL, NULL, NULL, 0);
    if (result) perror("HFS_REPLAY_JOURNAL");
    printf("HFS_REPLAY_JOURNAL: status=%d errno=%d\n", result, result ? errno : 0);
    int closed = close(descriptor);
    return result || closed;
}
