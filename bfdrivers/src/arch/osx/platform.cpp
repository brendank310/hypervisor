/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <platform.h>
#include <debug.h>

#include <libkern/OSMalloc.h>
#include <libkern/libkern.h>
#include <sys/conf.h>
#include <mach/mach_types.h>

extern "C" {
#include <kern/assert.h>
#include <kern/kext_alloc.h>
#define KERNEL_PRIVATE
#define MACH_KERNEL_PRIVATE
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>
#undef KERNEL_PRIVATE
#undef MACH_KERNEL_PRIVATE
}

#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>

OSMallocTag bf_mem_tag = NULL;
typedef int pmap_t;
extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);
extern vm_map_t kernel_map;

void *
platform_malloc(int64_t len)
{
    void *addr = NULL;

    if (len == 0)
    {
        IOLog("platform_alloc: invalid length\n");
        return addr;
    }

    addr = OSMalloc((uint32_t)len, bf_mem_tag);

    if (addr == NULL)
    {
        IOLog("platform_alloc: failed to vmalloc mem: %lld\n", len);
    }

    return addr;
}

void *
platform_virt_to_phys(void *virt)
{
    void *ptr = 0x00;
    IOMemoryDescriptor *mem_desc;

    mem_desc = IOMemoryDescriptor::withAddress(virt, 4096, kIODirectionInOut);

    mem_desc->prepare();

    ptr = (void *)mem_desc->getPhysicalAddress();

    return ptr;
}

void
platform_free(void *addr, int64_t len)
{
    if (addr == NULL)
    {
        IOLog("platform_free: invalid address %p\n", addr);
        return;
    }


    OSFree(addr, (uint32_t)len, bf_mem_tag);
}

int64_t
platform_mprotect(void *addr, uint64_t len, uint8_t prot)
{
    if (addr == NULL)
    {
        ALERT("platform_mprotect: invalid address\n");
        return -1;
    }

    if (len == 0)
    {
        ALERT("platform_mprotect: invalid length\n");
        return -2;
    }

    return 0;
}

void
platform_memset(void *ptr, char value, int64_t num)
{
    if (!ptr)
        return;

    memset(ptr, value, num);
}

void
platform_memcpy(void *dst, const void *src, int64_t num)
{
    if (!dst || !src)
        return;

    memcpy(dst, src, num);
}

void
platform_start()
{

}

void
platform_stop()
{

}
