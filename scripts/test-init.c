/* Minimal init for the CI boot test: proves the kernel reached userspace, then reboots. */
#include <fcntl.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    mkdir("/dev", 0755);
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    const char *message = "zeolite-init: reached userspace\n";
    int fd = open("/dev/console", O_WRONLY);
    if (fd >= 0) {
        write(fd, message, strlen(message));
        fsync(fd);
    }
    sync();
    reboot(RB_AUTOBOOT);
    for (;;) {
        pause();
    }
}
