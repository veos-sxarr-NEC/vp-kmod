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

#include <linux/sched.h>
#include <linux/mm_types.h>

int vp_gup(struct task_struct *tsk, struct mm_struct *mm, unsigned long start,
		unsigned long nr_pages, int write, int force,
		struct page **pages, struct vm_area_struct **vmas);

int check_vsyscall_area(uint64_t va);
