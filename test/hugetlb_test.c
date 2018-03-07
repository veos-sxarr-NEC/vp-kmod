#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "vp.h"

#define MMAP_SIZE (4*1024*1024)
int main(int argc, char **argv) {
	int i;
	int fd;
	void *addr;
	struct vp vp;
	uint64_t data;

	if (argc < 2) {
		fprintf(stderr, "specify data pattern\n");
		return 1;
	}

	addr = mmap(0, MMAP_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
	if (addr == (void *)-1) {
		fprintf(stderr, "mmap failed (%s)\n", strerror(errno));
		return 1;
	}
	printf("addr = %p\n", addr);

	data = strtoull(argv[1], NULL, 0);
	printf ("writing data (0x%lx)\n", data);
	for (i = 0; i < MMAP_SIZE/sizeof(uint64_t); i++)
		((uint64_t *)addr)[i] = data;

	vp.virt = (uint64_t)addr;
	vp.pid = getpid();
	vp.write = 1;

	fd = open("/dev/vp", O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "open %s failed (%s)\n", "/dev/vp", strerror(errno));
	        munmap(addr, MMAP_SIZE);
		return 1;
	}

	if (ioctl(fd, VP_CMD_V2P_PIN_DOWN, &vp)) {
		fprintf(stderr, "ioctl(VP_CMD_V2P) failed (%s)\n", strerror(errno));
		munmap(addr, MMAP_SIZE);
		return 1;
	}
	printf("pid = %d, virt = 0x%lx, phys = 0x%lx\n", vp.pid, vp.virt, vp.phys);
	if (ioctl(fd, VP_CMD_RELEASE, vp.phys)) {
		fprintf(stderr, "ioctl(VP_CMD_RELEASE) failed (%s)\n", strerror(errno));
		munmap(addr, MMAP_SIZE);
		return 1;
	}
	
	vp.virt += 4*1024+8;
	if (ioctl(fd, VP_CMD_V2P_PIN_DOWN, &vp)) {
		fprintf(stderr, "ioctl failed (%s)\n", strerror(errno));
		munmap(addr, MMAP_SIZE);
		return 1;
	}
	printf("pid = %d, virt = 0x%lx, phys = 0x%lx\n", vp.pid, vp.virt, vp.phys);
	
	if (ioctl(fd, VP_CMD_RELEASE, vp.phys)) {
		fprintf(stderr, "ioctl(VP_CMD_RELEASE) failed (%s)\n", strerror(errno));
		munmap(addr, MMAP_SIZE);
		return 1;
	}

	munmap(addr, MMAP_SIZE);

	return 0;
}
