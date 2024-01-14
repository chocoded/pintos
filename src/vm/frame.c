#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <debug.h>
#include <stddef.h>

/** The frame table. */
static struct list frame_list;

/** A global work for frame operation. */
static struct lock frame_lock;

/** Pointer for second chance algorithm. */
static struct list_elem *clock_ptr;

/** Helpers. */
static void frame_lock_acquire(void);
static void frame_lock_release(void);

static bool frame_insert(void *, struct sup_page_table_entry *);
static struct frame_table_entry *choose_victim(void);
static bool evict(void);

/** Initialize the frame table. */
void frame_init(void)
{
	list_init(&frame_list);
	lock_init(&frame_lock);
	clock_ptr = NULL;
}

/** Allocate a new frame, add it to the frame table and return its page. */
void *frame_alloc(enum palloc_flags flag, struct sup_page_table_entry *spte)
{
	void *kpage = palloc_get_page(flag);

	/** Can't allocate a new frame, must evict one. */
	if (kpage == NULL)
	{
		if (!evict())
		{
			PANIC("Can't evict any frame");
		}
		kpage = palloc_get_page(flag);
		if (kpage == NULL)
		{
			PANIC("Can't allocate any frame");
		}
	}
	if (!frame_insert(kpage, spte))
	{
		PANIC("Can't insert a frame into frame table");
	}
	return kpage;
}

/** Free a frame and its page. */
void frame_free(void *kpage)
{
	struct list_elem *e;
	frame_lock_acquire();
	for (e = list_begin(&frame_list); e != list_end(&frame_list);
		 e = list_next(e))
	{
		/** Find the frame. */
		struct frame_table_entry *fte = list_entry(e, struct frame_table_entry, lelem);
		if (fte->kpage == kpage)
		{
			/** Remove from the frame table and
			 * free the page and its entry. */
			list_remove(e);
			free(fte);
			fte = NULL;
			palloc_free_page(kpage);
			break;
		}
	}
	frame_lock_release();
}

/** Create a frame table entry and insert it into frame table. */
static bool frame_insert(void *kpage, struct sup_page_table_entry *spte)
{
	struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));
	if (fte == NULL)
		return false;

	fte->kpage = kpage;
	fte->spte = spte;
	fte->owner = thread_current();
	frame_lock_acquire();
	list_push_back(&frame_list, &fte->lelem);
	frame_lock_release();
	return true;
}

/** Second chance algorithm. */
static struct frame_table_entry *choose_victim(void)
{
	size_t frame_size = list_size(&frame_list);
	if (frame_size == 0)
		PANIC("Frame table is empty");

	for (size_t i = 0; i < frame_size + frame_size; ++i)
	{
		if (clock_ptr == NULL || clock_ptr == list_end(&frame_list))
		{
			clock_ptr = list_begin(&frame_list);
		}
		struct frame_table_entry *fte =
			list_entry(clock_ptr, struct frame_table_entry, lelem);

		clock_ptr = list_next(clock_ptr);
		if (fte->spte->pinned)
		{
			continue;
		}
		else if (pagedir_is_accessed(fte->owner->pagedir, fte->spte->upage))
		{
			pagedir_set_accessed(fte->owner->pagedir, fte->spte->upage, false);
			continue;
		}
		return fte;
	}

	PANIC("Can't evict any frame");
}

/** Evict a frame and remove its entry from frame table. */
static bool evict(void)
{
	frame_lock_acquire();

	/** Find the frame to be swapped out. */
	struct frame_table_entry *fte = choose_victim();
	struct sup_page_table_entry *spte = fte->spte;

	/** Write back. */
	if (pagedir_is_dirty(fte->owner->pagedir, spte->upage) ||
		spte->status == PAGE_SWAP)
	{
		if (spte->status == PAGE_MMAP)
		{
			file_lock_acquire();
			file_write_at(spte->file, fte->kpage,
						  spte->read_bytes,
						  spte->offset);
			file_lock_release();
		}
		else
		{
			spte->status = PAGE_SWAP;
			spte->swap_index = swap_out(fte->kpage);
		}
	}

	/** Clear its entry. */
	spte->loaded = false;
	list_remove(&fte->lelem);
	pagedir_clear_page(fte->owner->pagedir, spte->upage);
	palloc_free_page(fte->kpage);
	free(fte);
	fte = NULL;
	frame_lock_release();

	return true;
}

/** Acquire the lock for frame operation. */
static void frame_lock_acquire(void)
{
	lock_acquire(&frame_lock);
}

/** Release the lock for frame operation. */
static void frame_lock_release(void)
{
	lock_release(&frame_lock);
}
