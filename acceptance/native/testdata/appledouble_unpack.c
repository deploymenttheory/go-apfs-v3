/* A bounded launcher for Apple's public API, not an AppleDouble decoder.
 * Built and executed only by the verifier on guarded disposable macOS VMs.
 */
#include <copyfile.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: appledouble-unpack CONTROL DESTINATION\n");
        return 2;
    }
    if (copyfile(argv[1], argv[2], NULL, COPYFILE_UNPACK) != 0) {
        perror("copyfile COPYFILE_UNPACK");
        return 1;
    }
    return 0;
}
