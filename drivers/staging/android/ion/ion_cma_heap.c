/*
 * drivers/staging/android/ion/ion_cma_heap.c
 *
 * Copyright (C) Linaro 2012
 * Author: <benjamin.gaignard@linaro.org> for ST-Ericsson.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/err.h>
<<<<<<< HEAD
#include <linux/dma-mapping.h>

#include "ion.h"
#include "ion_priv.h"

#define ION_CMA_ALLOCATE_FAILED -1

struct ion_cma_heap {
	struct ion_heap heap;
	struct device *dev;
=======
#include <linux/cma.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>

#include "ion.h"

struct ion_cma_heap {
	struct ion_heap heap;
	struct cma *cma;
>>>>>>> v4.14.187
};

#define to_cma_heap(x) container_of(x, struct ion_cma_heap, heap)

<<<<<<< HEAD
struct ion_cma_buffer_info {
	void *cpu_addr;
	dma_addr_t handle;
	struct sg_table *table;
};

/* ION CMA heap operations functions */
static int ion_cma_allocate(struct ion_heap *heap, struct ion_buffer *buffer,
			    unsigned long len, unsigned long align,
			    unsigned long flags)
{
	struct ion_cma_heap *cma_heap = to_cma_heap(heap);
	struct device *dev = cma_heap->dev;
	struct ion_cma_buffer_info *info;

	dev_dbg(dev, "Request buffer allocation len %ld\n", len);

	if (buffer->flags & ION_FLAG_CACHED)
		return -EINVAL;

	if (align > PAGE_SIZE)
		return -EINVAL;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ION_CMA_ALLOCATE_FAILED;

	info->cpu_addr = dma_alloc_coherent(
			dev, len, &info->handle,
						GFP_HIGHUSER | __GFP_ZERO);

	if (!info->cpu_addr) {
		dev_err(dev, "Fail to allocate buffer\n");
		goto err;
	}

	info->table = kmalloc(sizeof(*info->table), GFP_KERNEL);
	if (!info->table)
		goto free_mem;

	if (dma_get_sgtable(dev, info->table, info->cpu_addr, info->handle,
			    len))
		goto free_table;
	/* keep this for memory release */
	buffer->priv_virt = info;
	buffer->sg_table = info->table;
	dev_dbg(dev, "Allocate buffer %p\n", buffer);
	return 0;

free_table:
	kfree(info->table);
free_mem:
	dma_free_coherent(dev, len, info->cpu_addr, info->handle);
err:
	kfree(info);
	return ION_CMA_ALLOCATE_FAILED;
=======
/* ION CMA heap operations functions */
static int ion_cma_allocate(struct ion_heap *heap, struct ion_buffer *buffer,
			    unsigned long len,
			    unsigned long flags)
{
	struct ion_cma_heap *cma_heap = to_cma_heap(heap);
	struct sg_table *table;
	struct page *pages;
	unsigned long size = PAGE_ALIGN(len);
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long align = get_order(size);
	int ret;

	if (align > CONFIG_CMA_ALIGNMENT)
		align = CONFIG_CMA_ALIGNMENT;

	pages = cma_alloc(cma_heap->cma, nr_pages, align, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	if (PageHighMem(pages)) {
		unsigned long nr_clear_pages = nr_pages;
		struct page *page = pages;

		while (nr_clear_pages > 0) {
			void *vaddr = kmap_atomic(page);

			memset(vaddr, 0, PAGE_SIZE);
			kunmap_atomic(vaddr);
			page++;
			nr_clear_pages--;
		}
	} else {
		memset(page_address(pages), 0, size);
	}

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		goto err;

	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret)
		goto free_mem;

	sg_set_page(table->sgl, pages, size, 0);

	buffer->priv_virt = pages;
	buffer->sg_table = table;
	return 0;

free_mem:
	kfree(table);
err:
	cma_release(cma_heap->cma, pages, nr_pages);
	return -ENOMEM;
>>>>>>> v4.14.187
}

static void ion_cma_free(struct ion_buffer *buffer)
{
	struct ion_cma_heap *cma_heap = to_cma_heap(buffer->heap);
<<<<<<< HEAD
	struct device *dev = cma_heap->dev;
	struct ion_cma_buffer_info *info = buffer->priv_virt;

	dev_dbg(dev, "Release buffer %p\n", buffer);
	/* release memory */
	dma_free_coherent(dev, buffer->size, info->cpu_addr, info->handle);
	/* release sg table */
	sg_free_table(info->table);
	kfree(info->table);
	kfree(info);
}

static int ion_cma_mmap(struct ion_heap *mapper, struct ion_buffer *buffer,
			struct vm_area_struct *vma)
{
	struct ion_cma_heap *cma_heap = to_cma_heap(buffer->heap);
	struct device *dev = cma_heap->dev;
	struct ion_cma_buffer_info *info = buffer->priv_virt;

	return dma_mmap_coherent(dev, vma, info->cpu_addr, info->handle,
				 buffer->size);
}

static void *ion_cma_map_kernel(struct ion_heap *heap,
				struct ion_buffer *buffer)
{
	struct ion_cma_buffer_info *info = buffer->priv_virt;
	/* kernel memory mapping has been done at allocation time */
	return info->cpu_addr;
}

static void ion_cma_unmap_kernel(struct ion_heap *heap,
				 struct ion_buffer *buffer)
{
=======
	struct page *pages = buffer->priv_virt;
	unsigned long nr_pages = PAGE_ALIGN(buffer->size) >> PAGE_SHIFT;

	/* release memory */
	cma_release(cma_heap->cma, pages, nr_pages);
	/* release sg table */
	sg_free_table(buffer->sg_table);
	kfree(buffer->sg_table);
>>>>>>> v4.14.187
}

static struct ion_heap_ops ion_cma_ops = {
	.allocate = ion_cma_allocate,
	.free = ion_cma_free,
<<<<<<< HEAD
	.map_user = ion_cma_mmap,
	.map_kernel = ion_cma_map_kernel,
	.unmap_kernel = ion_cma_unmap_kernel,
};

struct ion_heap *ion_cma_heap_create(struct ion_platform_heap *data)
=======
	.map_user = ion_heap_map_user,
	.map_kernel = ion_heap_map_kernel,
	.unmap_kernel = ion_heap_unmap_kernel,
};

static struct ion_heap *__ion_cma_heap_create(struct cma *cma)
>>>>>>> v4.14.187
{
	struct ion_cma_heap *cma_heap;

	cma_heap = kzalloc(sizeof(*cma_heap), GFP_KERNEL);

	if (!cma_heap)
		return ERR_PTR(-ENOMEM);

	cma_heap->heap.ops = &ion_cma_ops;
	/*
	 * get device from private heaps data, later it will be
	 * used to make the link with reserved CMA memory
	 */
<<<<<<< HEAD
	cma_heap->dev = data->priv;
=======
	cma_heap->cma = cma;
>>>>>>> v4.14.187
	cma_heap->heap.type = ION_HEAP_TYPE_DMA;
	return &cma_heap->heap;
}

<<<<<<< HEAD
void ion_cma_heap_destroy(struct ion_heap *heap)
{
	struct ion_cma_heap *cma_heap = to_cma_heap(heap);

	kfree(cma_heap);
}
=======
static int __ion_add_cma_heaps(struct cma *cma, void *data)
{
	struct ion_heap *heap;

	heap = __ion_cma_heap_create(cma);
	if (IS_ERR(heap))
		return PTR_ERR(heap);

	heap->name = cma_get_name(cma);

	ion_device_add_heap(heap);
	return 0;
}

static int ion_add_cma_heaps(void)
{
	cma_for_each_area(__ion_add_cma_heaps, NULL);
	return 0;
}
device_initcall(ion_add_cma_heaps);
>>>>>>> v4.14.187
