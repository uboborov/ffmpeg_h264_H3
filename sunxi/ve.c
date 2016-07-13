/*
 * Copyright (c) 2013-2014 Jens Kuske <jenskuske@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/file.h>
#include "ve.h"
#include "ion.h"
#include "ion_sunxi.h"
#include "cedar_ve.h"

#define LOCKFILE "/tmp/cedar_dev.lck"
#define DEVICE "/dev/cedar_dev"
#define PAGE_OFFSET (0xc0000000) // from kernel
#define PAGE_SIZE (4096)

#define typeof __typeof__

#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

static int fd = -1, lockfd = -1;	
//void memlist_add(struct ve_mem *mem);	
//struct mem_list *memlist_find(struct ve_mem *mem);
//int memlist_del(struct ve_mem *mem);
//void memlist_del_all();

struct memchunk_t
{
	struct ve_mem mem;
	struct memchunk_t *next;
};

struct ion_mem
{
	struct ion_handle *handle;
	int fd;
	struct ve_mem mem;
};

static struct
{
	int fd;
	int ion_fd;
	void *regs;
	int version;
	struct memchunk_t first_memchunk;
	pthread_rwlock_t memory_lock;
	pthread_mutex_t device_lock;
} ve = { .fd = -1, .ion_fd = -1, .memory_lock = PTHREAD_RWLOCK_INITIALIZER, .device_lock = PTHREAD_MUTEX_INITIALIZER };


struct mem_list {
	struct ve_mem *mem;
	struct mem_list *next;
} *memlist = NULL;

static void memlist_add(struct ve_mem *mem) {
	struct mem_list *m, *k;
	if (memlist == NULL) {
		memlist = (struct mem_list *)malloc(sizeof (struct mem_list));
		memlist->mem = mem;
		memlist->next = NULL;
		return;
	}
	m = k = memlist;
	while (m) {
		k = m;
		m = m->next;
	}
	m = (struct mem_list *)malloc(sizeof (struct mem_list));
	m->mem = mem;
	m->next = NULL;
	k->next = m;
}

static struct mem_list *memlist_find(struct ve_mem *mem) {
	struct mem_list *m = memlist;
	
	while (m) {
		if (m->mem == mem) return m;
		m = m->next;
	}
	return NULL;
}

static int memlist_del(struct ve_mem *mem) {
	struct mem_list *m = memlist;
	struct mem_list *prev = m;
	
	while (m) {
		if (m->mem == mem) {
			prev->next = m->next;
			free(m);
			return 0;
		}
		prev = m;
		m = m->next;
	}
	return -1;
}

static void memlist_del_all(void) {
	struct mem_list *m = memlist;
	
	while (m) {
		struct mem_list *k = m;
		m = m->next;
		free(k);
	}
	memlist = NULL;
}

int ve_open(void)
{
	if (ve.fd != -1)
		return 0;

	struct cedarv_env_infomation info;

	ve.fd = open(DEVICE, O_RDWR);
	if (ve.fd == -1)
		return 0;

	if (ioctl(ve.fd, IOCTL_GET_ENV_INFO, (void *)(&info)) == -1)
		goto close;

	ve.regs = mmap(NULL, 0x800, PROT_READ | PROT_WRITE, MAP_SHARED, ve.fd, info.address_macc);
	if (ve.regs == MAP_FAILED)
		goto close;

	ve.first_memchunk.mem.phys = info.phymem_start - PAGE_OFFSET;
	ve.first_memchunk.mem.size = info.phymem_total_size;

	if (ve.first_memchunk.mem.size == 0)
	{
		ve.ion_fd = open("/dev/ion", O_RDONLY);
		if (ve.ion_fd == -1)
			goto unmap;
	}

	ioctl(ve.fd, IOCTL_ENGINE_REQ, 0);
	ioctl(ve.fd, IOCTL_ENABLE_VE, 0);
	ioctl(ve.fd, IOCTL_SET_VE_FREQ, 320);
	ioctl(ve.fd, IOCTL_RESET_VE, 0);

	writel(0x00130007, ve.regs + VE_CTRL);

	ve.version = readl(ve.regs + VE_VERSION) >> 16;
	printf("[VDPAU SUNXI] VE version 0x%04x opened.\n", ve.version);

	return 1;

unmap:
	munmap(ve.regs, 0x800);
close:
	close(ve.fd);
	ve.fd = -1;
	return 0;
}

int ve_lock(void) {
	/* We must lock another file than /dev/cedar_dev, 
	 * because opening the device already do problems.
	 * (If device is opened, it will be closed at program exit and ve
	 * interrupt will be disabled, also if anohter process was using it) */
	if(lockfd == -1) lockfd = open(LOCKFILE, O_CREAT | O_RDWR, 0666);
	if(lockfd == -1) return 0;
	if(flock(lockfd, LOCK_EX | LOCK_NB) < 0) return 0;
	return 1;
}

void ve_unlock(void) {
	if (lockfd == -1) return;
	flock(lockfd, LOCK_UN);
	close(lockfd);
	lockfd = -1;
	/* Don't try to unlink file, it causes race conditions. */
}

void ve_close(void)
{
	if (ve.fd == -1)
		return;

	ioctl(ve.fd, IOCTL_DISABLE_VE, 0);
	ioctl(ve.fd, IOCTL_ENGINE_REL, 0);

	munmap(ve.regs, 0x800);
	ve.regs = NULL;

	if (ve.ion_fd != -1)
		close(ve.ion_fd);

	close(ve.fd);
	ve.fd = -1;
}

int ve_get_version(void)
{
	return ve.version;
}

int ve_wait(int timeout)
{
	if (ve.fd == -1)
		return 0;
	if (ve_get_version() >= 0x1633)
		return ioctl(ve.fd, IOCTL_WAIT_VE_EN, timeout);
	else
		return ioctl(ve.fd, IOCTL_WAIT_VE_DE, timeout);
}

void *ve_get(int engine, uint32_t flags)
{
	if (pthread_mutex_lock(&ve.device_lock))
		return NULL;
	if (ve_get_version() >= 0x1633)
		writel(0x001300C0 | (engine & 0xf) | (flags & ~0xf), ve.regs + VE_CTRL);
	else
		writel(0x00130000 | (engine & 0xf) | (flags & ~0xf), ve.regs + VE_CTRL);

	return ve.regs;
}

void ve_put(void)
{
	writel(0x00130007, ve.regs + VE_CTRL);
	pthread_mutex_unlock(&ve.device_lock);
}

static struct ve_mem *ion_malloc(int size)
{
	struct ion_mem *imem = calloc(1, sizeof(struct ion_mem));
	if (!imem)
	{
		perror("calloc ion_buffer failed");
		return NULL;
	}

	struct ion_allocation_data alloc = {
		.len = size,
		.align = 4096,
		.heap_id_mask = ION_HEAP_TYPE_DMA,
		.flags = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC,
	};

	if (ioctl(ve.ion_fd, ION_IOC_ALLOC, &alloc))
	{
		perror("ION_IOC_ALLOC failed");
		free(imem);
		return NULL;
	}

	imem->handle = alloc.handle;
	imem->mem.size = size;

	struct ion_fd_data map = {
		.handle = imem->handle,
	};

	if (ioctl(ve.ion_fd, ION_IOC_MAP, &map))
	{
		perror("ION_IOC_MAP failed");
		free(imem);
		return NULL;
	}

	imem->fd = map.fd;

	imem->mem.virt = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, imem->fd, 0);
	if (imem->mem.virt == MAP_FAILED)
	{
		perror("mmap failed");
		return NULL;
	}

	sunxi_phys_data phys = {
		.handle = imem->handle,
	};

	struct ion_custom_data custom = {
		.cmd = ION_IOC_SUNXI_PHYS_ADDR,
		.arg = (unsigned long)(&phys),
	};

	if (ioctl(ve.ion_fd, ION_IOC_CUSTOM, &custom))
	{
		perror("ION_IOC_CUSTOM(SUNXI_PHYS_ADDR) failed");
		free(imem);
		return NULL;
	}

	imem->mem.phys = phys.phys_addr - 0x40000000;

	memlist_add(&imem->mem);
	
	return &imem->mem;
}

struct ve_mem *ve_malloc(int size)
{
	if (ve.fd == -1)
		return NULL;

	if (ve.ion_fd != -1)
		return ion_malloc(size);

	if (pthread_rwlock_wrlock(&ve.memory_lock))
		return NULL;

	void *addr = NULL;
	struct ve_mem *ret = NULL;

	size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	struct memchunk_t *c, *best_chunk = NULL;
	for (c = &ve.first_memchunk; c != NULL; c = c->next)
	{
		if(c->mem.virt == NULL && c->mem.size >= size)
		{
			if (best_chunk == NULL || c->mem.size < best_chunk->mem.size)
				best_chunk = c;

			if (c->mem.size == size)
				break;
		}
	}

	if (!best_chunk)
		goto out;

	int left_size = best_chunk->mem.size - size;

	addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, ve.fd, best_chunk->mem.phys + PAGE_OFFSET);
	if (addr == MAP_FAILED)
	{
		ret = NULL;
		goto out;
	}

	best_chunk->mem.virt = addr;
	best_chunk->mem.size = size;

	if (left_size > 0)
	{
		c = malloc(sizeof(struct memchunk_t));
		c->mem.phys = best_chunk->mem.phys + size;
		c->mem.size = left_size;
		c->mem.virt = NULL;
		c->next = best_chunk->next;
		best_chunk->next = c;
	}

	ret = &best_chunk->mem;
out:
	pthread_rwlock_unlock(&ve.memory_lock);
	return ret;
}

static void ion_free(struct ve_mem *mem)
{
	if (ve.ion_fd == -1 || !mem)
		return;

	struct ion_mem *imem = container_of(mem, struct ion_mem, mem);

	if (munmap(mem->virt, mem->size))
	{
		perror("munmap failed");
		return;
	}
	
	memlist_del(mem);

	close(imem->fd);

	struct ion_handle_data handle = {
		.handle = imem->handle,
	};

	if (ioctl(ve.ion_fd, ION_IOC_FREE, &handle))
	{
		perror("ION_IOC_FREE failed");
		free(imem);
		return;
	}
}

void ve_free(struct ve_mem *mem)
{
	if (ve.fd == -1)
		return;

	if (mem == NULL)
		return;

	if (ve.ion_fd != -1)
		ion_free(mem);

	if (pthread_rwlock_wrlock(&ve.memory_lock))
		return;

	struct memchunk_t *c;
	for (c = &ve.first_memchunk; c != NULL; c = c->next)
	{
		if (&c->mem == mem)
		{
			munmap(c->mem.virt, c->mem.size);
			c->mem.virt = NULL;
			break;
		}
	}

	for (c = &ve.first_memchunk; c != NULL; c = c->next)
	{
		if (c->mem.virt == NULL)
		{
			while (c->next != NULL && c->next->mem.virt == NULL)
			{
				struct memchunk_t *n = c->next;
				c->mem.size += n->mem.size;
				c->next = n->next;
				free(n);
			}
		}
	}

	pthread_rwlock_unlock(&ve.memory_lock);
}

uint32_t ve_virt2phys(void *ptr)
{
	uint32_t addr = 0;
	
	if (ve.fd == -1)
		return 0;
	
	if (ve.ion_fd != -1) {
		
		struct mem_list *m = memlist;
		
		while (m) {
			struct ve_mem *mem = m->mem;
			if (!mem) {
				m = m->next;
				continue;
			}
			
			//printf("c->mem: virt 0x%08X, phys 0x%08X, ptr 0x%08X\n", (unsigned int)mem->virt, mem->phys, (unsigned int)ptr);
			if (mem->virt == NULL)
				continue;

			if (mem->virt == ptr)
			{
				addr = mem->phys;
				break;
			}
			else if (ptr > mem->virt && ptr < (mem->virt + mem->size))
			{
				addr = mem->phys + (ptr - mem->virt);
				break;
			}
			m = m->next;
		}
		return addr;
	}
	

	//if (pthread_rwlock_rdlock(&ve.memory_lock))
	//	return 0;

	

	struct memchunk_t *c;
	for (c = &ve.first_memchunk; c != NULL; c = c->next)
	{
		printf("c->mem: virt 0x%08X, phys 0x%08X, ptr 0x%08X\n", (unsigned int)c->mem.virt, c->mem.phys, (unsigned int)ptr);
		if (c->mem.virt == NULL)
			continue;

		if (c->mem.virt == ptr)
		{
			addr = c->mem.phys;
			break;
		}
		else if (ptr > c->mem.virt && ptr < (c->mem.virt + c->mem.size))
		{
			addr = c->mem.phys + (ptr - c->mem.virt);
			break;
		}
	}

	//pthread_rwlock_unlock(&ve.memory_lock);
	return addr;
}


void ve_flush_cache(struct ve_mem *mem)
{
	if (ve.fd == -1)
		return;

	if (ve.ion_fd != -1)
	{
		sunxi_cache_range range = {
			.start = (long)mem->virt,
			.end = (long)mem->virt + mem->size,
		};

		struct ion_custom_data cache = {
			.cmd = ION_IOC_SUNXI_FLUSH_RANGE,
			.arg = (unsigned long)(&range),
		};

		if (ioctl(ve.ion_fd, ION_IOC_CUSTOM, &cache))
			perror("ION_IOC_CUSTOM(SUNXI_FLUSH_RANGE) failed");
	}
	else
	{
		struct cedarv_cache_range range =
		{
			.start = (int)mem->virt,
			.end = (int)mem->virt + mem->size
		};

		ioctl(ve.fd, IOCTL_FLUSH_CACHE, (void*)(&range));
	}
}
