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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/huge_mm.h>
#include <linux/rmap.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <asm/pgtable.h>
#include <linux/init.h>
#include <linux/vmalloc.h>

#include "../config.h"
#include "commitid.h"
#include "vp.h"
#include "compat.h"
#define NAME "vp"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NEC Corporation");
MODULE_DESCRIPTION("Virt to Phys Kernel Module");
MODULE_VERSION(VERSION);
MODULE_INFO(release, RELEASE);
MODULE_INFO(gitcom, COMMITID);

struct vp_gup_page {
	struct page *page;	/*!< pointer to the page */
	struct hlist_node list;	/*!< list */
};

#ifdef DEBUG
static struct page_list hash_page_list;
static struct mutex vp_list_lock;
static long vp_ioctl(struct file *, unsigned int, unsigned long);
static const struct file_operations vp_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = vp_ioctl,
};
#endif

static struct miscdevice v2p_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = NAME,
#ifdef DEBUG
	.fops = &vp_fops,
#endif
};

#define vp_trace() dev_dbg(v2p_dev.this_device, "trace")
#define vp_dbg(fmt, args...) dev_dbg(v2p_dev.this_device, fmt, ## args)
#define vp_err(fmt, args...) dev_err(v2p_dev.this_device, fmt, ## args)
#define vp_info(fmt, args...) dev_info(v2p_dev.this_device, fmt, ## args)
#define vp_warn(fmt, args...) dev_warn(v2p_dev.this_device, fmt, ## args)

/**
 * @brief Release (decrement reference count) single page which was
 * pinned down by this module
 *
 * @param pa: Physical address of the page
 *
 * @return 0 on success.
 *         -EINVAL on invalid argument.
 *         -ESRCH when the page is not pinned down by this module.
 */
int vp_page_release(unsigned long pa, struct page_list *hash_list_head)
{
	unsigned long pfn;
	struct page *pfnpage;
	struct hlist_node *n;
	struct vp_gup_page *gup_page;
	struct hlist_head *hash_head;

	vp_trace();

	/* Check if page related to this physical address is exists */
	pfn = pa >> PAGE_SHIFT;
	if (page_is_ram(pfn) && !pfn_valid(pfn)) {
		vp_dbg("pfn_valid() returns false (pfn = %lx).\n", pfn);
		return -EINVAL;
	}

	pfnpage = pfn_to_page(pfn);
	if (!pfnpage) {
		vp_dbg("pfn_to_page() returns NULL (pfn = %lx).\n", pfn);
		return -EINVAL;
	}

	hash_head = &hash_list_head->head[hash_min(pfn, HASH_BITS(hash_list_head->head))];

	if (hash_head->first) {
		hlist_for_each_entry_safe(gup_page, n, hash_head, list) {
			if (gup_page->page == pfnpage) {
				put_page(gup_page->page);
				vp_dbg("pfn(0x%lx) page count = %d\n",
						page_to_pfn(gup_page->page),
						page_count(gup_page->page));
				hash_del(&gup_page->list);
				kfree(gup_page);
				return 0;
			}
		}
	}
	return -ESRCH;
}
EXPORT_SYMBOL(vp_page_release);

/**
 * @brief Relase (decrement reference count) all pages which were pinned
 * by this module.
 */
void vp_page_release_all(struct page_list *hash_list_head)
{
	struct hlist_node *tmp;
	struct vp_gup_page *gup_page;
	int i;

	vp_trace();

	hash_for_each_safe(hash_list_head->head, i, tmp, gup_page, list) {
		put_page(gup_page->page);

		vp_dbg("pfn(0x%lx) page count = %d\n",
				page_to_pfn(gup_page->page),
				page_count(gup_page->page));
		hash_del(&gup_page->list);
		kfree(gup_page);
	}
}
EXPORT_SYMBOL(vp_page_release_all);

/**
 * @brief Translate page into physical address
 *
 * @param[in] page: struct page to translate
 * @param va: Virtual address used for calculate offset
 *            from page aligned address.
 * @param[out] pa: Physical address
 *
 * @return 0 on success.
 *         -EINVAL on invalid page.
 */
static int vp_page_to_pa(struct page *page, unsigned long va, unsigned long *pa)
{
	unsigned long pfn;

	if (!page)
		return -EINVAL;

	pfn = page_to_pfn(page);
	if (page_is_ram(pfn) && !pfn_valid(pfn)) {
		vp_dbg("pfn_valid() returns false (pfn = %lx).\n", pfn);
		return -EINVAL;
	}

	*pa = (pfn << PAGE_SHIFT) + (va & ~PAGE_MASK);
	return 0;

}

/**
 * @brief Add get user paged page to the list
 *
 * @param[in] page: the page to be added
 *
 * @return 0 on success.
 *         -EINVAL on invalid page
 *         -ENOMEM on memory allocation failure
 */
static int vp_add_gup_page_list(struct page *page,
		struct page_list *hash_list_head)
{
	struct vp_gup_page *gup_page;
	unsigned long pfn;

	vp_trace();

	if (!page)
		return -EINVAL;

	gup_page = kmalloc(sizeof(struct vp_gup_page), GFP_KERNEL);
	if (!gup_page)
		return -ENOMEM;

	gup_page->page = page;
	pfn = page_to_pfn(gup_page->page);
	hash_add(hash_list_head->head, &gup_page->list, pfn);
	vp_dbg("pfn(0x%lx) page count = %d\n",
			pfn, page_count(gup_page->page));

	return 0;
}

/* Translate virtual address (VM_PFNMAP) into phisical address */
static int vp_walk_page(unsigned long va, unsigned long *pa,
		struct mm_struct *mm)
{
	unsigned long pfn;

	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd)) {
		vp_dbg("invalid pgd\n");
		return -ESRCH;
	}
	pud = pud_offset(pgd, va);
	if (pud_none(*pud)) {
		vp_dbg("invalid pud\n");
		return -ESRCH;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd)) {
		vp_dbg("invalid pmd\n");
		return -ESRCH;
	}
	pte = pte_offset_map(pmd, va);
	if (pte_none(*pte)) {
		vp_dbg("invalid pte\n");
		return -ESRCH;
	}
	pfn = pte_pfn(*pte);
	if (page_is_ram(pfn) && !pfn_valid(pfn)) {
		vp_dbg("pfn_valid() returns false (pfn = %lx).\n", pfn);
		return -EINVAL;
	}

	*pa = (pfn << PAGE_SHIFT) + (va & ~PAGE_MASK);
	pte_unmap(pte);

	return 0;
}

/**
 * @brief Translate virtual address into physical address
 *
 * @param[in] v: pid, vaddr, paddr, write flag
 * @param pin_down: 1 if pages will be written. 0 if pages won't be written.
 *
 * @return 0 on success.
 *         -ESRCH if related page structure is not found.
 *         -ENOMEM on memory allocation failure.
 *         -errno if failed to get_user_pages().
 */
int vp_v2p(struct vp *v, int pin_down, struct page_list *hash_list_head)
{
	int ret = 0;
	int gup_pinned = 0;
	uint64_t va, pa;
	struct pid *pid;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct page *pages[1];

	pid = find_get_pid(v->pid);
	if (!pid)
		return -ESRCH;

	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!task)
		return -ESRCH;

	va = v->virt;
	ret = check_vsyscall_area(va);
	if (ret != 0)
		return ret;

	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -ESRCH;

	/* mmap_sem must be held during get_user_pages() */
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, va);
	if (!vma || (vma->vm_mm && vma->vm_start
				== (long)vma->vm_mm->context.vdso)) {
		up_read(&mm->mmap_sem);
		mmput(mm);
		return -EINVAL;
	}

	/*
	 * In the case of VM_PFNMAP, just walk the page table and
	 * acquire physical address.
	 */
	if (vma->vm_flags & VM_PFNMAP) {
		ret = vp_walk_page(va, (unsigned long *)&pa, mm);
		up_read(&mm->mmap_sem);
		mmput(mm);
		if (!ret) {
			v->phys = pa;
			v->pfnmap = 1;
			vp_dbg("pid(%d) %p, pa = %p\n",
					v->pid, (void *)va, (void *)pa);
		}
		return ret;
	}
	v->pfnmap = 0;

	/* Pin down just one page */
	gup_pinned = vp_gup(task, mm, va, 1, v->write, 0, pages, NULL);
	up_read(&mm->mmap_sem);
	mmput(mm);
	if (gup_pinned != 1) {
		vp_dbg("Failed to pin down the page\n");
		vp_dbg("ret = %d, pid = %d, address = %p, write = %d\n",
				gup_pinned, v->pid, (void *)va, v->write);
		if (gup_pinned < 0) {
			ret = gup_pinned;
		} else { /* gup_pinned == 0 */
			ret = -ENOMEM;
		}
		return ret;
	}

	ret = vp_page_to_pa(pages[0], va, (unsigned long *)&pa);
	if (ret)
		goto err_gup;

	v->phys = pa;
	vp_dbg("pid(%d) %p, pa = %p, pin_down = %d\n",
			v->pid, (void *)va, (void *)pa, pin_down);

	if (pin_down) {
		ret = vp_add_gup_page_list(pages[0], hash_list_head);
		/* If success, keep the page pinned */
		if (ret)
			goto err_gup;
		return 0;
	}

err_gup:
	put_page(pages[0]);

	return ret;
}
EXPORT_SYMBOL(vp_v2p);

/**
 * @brief Virtual address into physicall address from user-space
 *
 * @param[in, out] uptr: user space address pointer
 * @param pin_down: 1 if page will be pinned down.
 *
 * @return 0 on success.
 *         -EFAULT on memory copy failure between user-space and kernel-space.
 *         -errno if failed to vp_v2p().
 */
int vp_v2p_from_user(struct vp __user *uptr, int pin_down,
		struct page_list *hash_list_head)
{
	int ret;
	struct vp vp_k;

	ret = get_user(vp_k.virt, &uptr->virt);
	if (ret)
		return -EFAULT;
	ret = get_user(vp_k.pid, &uptr->pid);
	if (ret)
		return -EFAULT;
	ret = get_user(vp_k.write, &uptr->write);
	if (ret)
		return -EFAULT;
	ret = vp_v2p(&vp_k, pin_down, hash_list_head);
	if (ret)
		return ret;
	ret = put_user(vp_k.phys, &uptr->phys);
	if (ret)
		goto err_after_v2p;
	ret = put_user(vp_k.pfnmap, &uptr->pfnmap);
	if (ret)
		goto err_after_v2p;

	return 0;

err_after_v2p:
	if (pin_down && !vp_k.pfnmap) {
		ret = vp_page_release(vp_k.phys, hash_list_head);
		if (ret)
			return ret;
	}
	return -EFAULT;
}
EXPORT_SYMBOL(vp_v2p_from_user);

#ifdef DEBUG
long vp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	mutex_lock(&vp_list_lock);
	switch (cmd) {
	case VP_CMD_V2P:
		ret = vp_v2p_from_user((struct vp __user *)arg, 0, &hash_page_list);
		break;
	case VP_CMD_V2P_PIN_DOWN:
		ret = vp_v2p_from_user((struct vp __user *)arg, 1, &hash_page_list);
		break;
	case VP_CMD_RELEASE:
		ret = vp_page_release(arg, &hash_page_list);
		break;
	case VP_CMD_RELEASE_ALL:
		vp_page_release_all(&hash_page_list);
		break;
	}
	mutex_unlock(&vp_list_lock);

	return ret;
}
#endif

/**
 * @brief init vp module
 *
 * @return 0 on success.
 *         -errno on failure.
 */
int vp_init(void)
{
	int ret;

	pr_info("misc %s: module init\n", NAME);

	ret = misc_register(&v2p_dev);
	if (ret < 0)
		pr_err("cannot register misc device (%d)\n", ret);

#ifdef DEBUG
	mutex_init(&vp_list_lock);
#endif

	return ret;
}
module_init(vp_init);

/**
 * @brief exit vp module
 */
void __exit vp_fini(void)
{
	pr_info("misc %s: module exit\n", NAME);
#ifdef DEBUG
	vp_page_release_all(&hash_page_list);
#endif
	misc_deregister(&v2p_dev);
}
module_exit(vp_fini);
