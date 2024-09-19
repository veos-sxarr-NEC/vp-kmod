/*
 * VP Kernel Module
 *
 * Copyright (C) 2017-2018 NEC Corporation
 * This file is part of VP Kernel Module.
 *
 * VP Kernel Module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * VP Kernel Module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with the VP Kernel Module; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <linux/mm.h>
#include "compat.h"

int check_vsyscall_area(uint64_t va)
{
#if (KERNEL_VERSION(3, 16, 0) > LINUX_VERSION_CODE)
	if (va >= VSYSCALL_START && va <= VSYSCALL_START +
			(VSYSCALL_MAPPED_PAGES * PAGE_SIZE))
		return -EINVAL;
	return 0;
#else
	if (va >= VSYSCALL_ADDR && va <= VSYSCALL_ADDR + PAGE_SIZE)
		return -EINVAL;
	return 0;
#endif
}

int vp_gup(struct task_struct *tsk, struct mm_struct *mm, unsigned long start,
		unsigned long nr_pages, int write, int force,
		struct page **pages, struct vm_area_struct **vmas)
{
#if (KERNEL_VERSION(4, 6, 0) > LINUX_VERSION_CODE)
	return get_user_pages(tsk, mm, start, nr_pages, write, force, pages,
			vmas);
#elif (KERNEL_VERSION(4, 9, 0) > LINUX_VERSION_CODE)
	return get_user_pages_remote(tsk, mm, start, nr_pages, write, force,
					pages, vmas);
#else
	unsigned int gup_flags = 0;
	if (write)
		gup_flags |= FOLL_WRITE;
	if (force)
		gup_flags |= FOLL_FORCE;
#if (KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE)
	return get_user_pages_remote(tsk, mm, start, nr_pages, gup_flags,
					pages, vmas);
#elif (KERNEL_VERSION(5, 0, 0) > LINUX_VERSION_CODE)
	return get_user_pages_remote(tsk, mm, start, nr_pages, gup_flags,
					pages, vmas,NULL);
#else
	return get_user_pages_remote(mm, start, nr_pages, gup_flags,
					pages, vmas,NULL);
#endif

#endif
}


pud_t * vp_pud_offset( pgd_t *pgd ,unsigned long va )
{
        pud_t *pud;
#if (KERNEL_VERSION(4, 10, 0) <= LINUX_VERSION_CODE)
        p4d_t *p4d;
        p4d = p4d_offset(pgd, va);
        pud = pud_offset(p4d, va);
#else
        pud = pud_offset(pgd, va);
#endif
        return pud;
}
