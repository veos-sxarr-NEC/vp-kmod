#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include "vp.h"

int main(void) {
	int fd;
	int vpfd;
	void *pfnmap_addr;
	void *anon_addr;
	struct vp vp;

	anon_addr = malloc(1*1024*1024);
	if (anon_addr == (void *)-1) {
		perror("malloc fail");
		exit(1);
	}

	fd = open("/dev/ve0", O_RDWR);
	if (fd == -1) {
		perror("/dev/ve0");
		exit(1);
	}

	pfnmap_addr = mmap(0, 1*1024*1024, PROT_WRITE, MAP_SHARED,
			fd, 256*1024*1024);
	if (pfnmap_addr == (void *)-1) {
		perror("mmap");
		exit(1);
	}
	memcpy(anon_addr, pfnmap_addr, 1*1024*1024);

	vpfd = open("/dev/vp", O_RDWR);
	if (vpfd == -1) {
		perror("/dev/vp");
		exit(1);
	}

	vp.pid = getpid();
	vp.write = 1;
	vp.virt = (uint64_t)anon_addr;
	if (ioctl(vpfd, VP_CMD_V2P_PIN_DOWN, &vp)) {
		perror("vpfd");
		fprintf(stderr, "VP_CMD_V2P_PIN_DOWN failed\n");
		exit(1);
	}
	printf("anon: pid = %d, virt = 0x%lx, phys = 0x%lx\n",
			vp.pid, vp.virt, vp.phys);

	vp.virt = (uint64_t)pfnmap_addr;
	if (ioctl(vpfd, VP_CMD_V2P_PIN_DOWN, &vp)) {
		perror("vpfd");
		fprintf(stderr, "VP_CMD_V2P_PIN_DOWN failed\n");
		exit(1);
	}
	printf("pfnmap: pid = %d, virt = 0x%lx, phys = 0x%lx\n",
			vp.pid, vp.virt, vp.phys);

	ioctl(vpfd, VP_CMD_RELEASE_ALL, NULL);

	return 0;
}
