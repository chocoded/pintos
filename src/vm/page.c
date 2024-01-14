#include "vm/page.h"
#include "vm/frame.h"
#include <string.h>
#include <debug.h>
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

/** Helpers. */
static unsigned spte_hash(const struct hash_elem *e,
                          void *aux UNUSED);
static bool spte_less(const struct hash_elem *a,
                      const struct hash_elem *b,
                      void *aux UNUSED);
static void spte_destroy(struct hash_elem *e,
                         void *aux UNUSED);

/** Create a supplyment page table. */
struct sup_page_table *spt_create(void)
{
    struct sup_page_table *spt =
        malloc(sizeof(struct sup_page_table));
    if (spt == NULL)
        PANIC("Can't create page table");

    hash_init(&spt->page_map, spte_hash, spte_less, NULL);
    lock_init(&spt->page_lock);
    return spt;
}

/** Destroy the supplyment page table. */
void spt_destroy(struct sup_page_table *spt)
{
    ASSERT(spt != NULL);

    hash_destroy(&spt->page_map, spte_destroy);
    free(spt);
}

/** Find the supplyment page table entry by the given page. */
struct sup_page_table_entry *spt_lookup(void *uaddr)
{
    struct sup_page_table *spt = thread_current()->spt;

    struct sup_page_table_entry spte;
    spte.upage = pg_round_down(uaddr);
    lock_acquire(&spt->page_lock);
    struct hash_elem *e = hash_find(&spt->page_map, &spte.helem);
    lock_release(&spt->page_lock);
    if (e == NULL)
        return NULL;

    return hash_entry(e, struct sup_page_table_entry, helem);
}

/** Load a page from file for case PAGE_FILE and PAGE_MMAP . */
bool load_file(struct sup_page_table_entry *spte)
{
    /** Allocate a frame. */
    enum palloc_flags flag = PAL_USER;
    if (spte->read_bytes == 0)
        flag |= PAL_ZERO;

    uint8_t *frame = frame_alloc(flag, spte);
    if (!frame)
        return false;

    /** Read the data into the page. */
    if (spte->read_bytes > 0)
    {
        file_lock_acquire();
        if ((int)spte->read_bytes != file_read_at(spte->file, frame,
                                                  spte->read_bytes,
                                                  spte->offset))
        {
            file_lock_release();
            frame_free(frame);
            return false;
        }
        file_lock_release();
        memset(frame + spte->read_bytes, 0, spte->zero_bytes);
    }

    /** Install the page. */
    if (!install_page(spte->upage, frame, spte->writable))
    {
        frame_free(frame);
        return false;
    }

    spte->loaded = true;
    return true;
}

/** Load a page from swap space for case PAGE_SWAP. */
bool load_swap(struct sup_page_table_entry *spte)
{
    /** Allocate a frame. */
    uint8_t *frame = frame_alloc(PAL_USER, spte);
    if (!frame)
        return false;

    /** Install the page. */
    if (!install_page(spte->upage, frame, spte->writable))
    {
        frame_free(frame);
        return false;
    }

    /** Swap in the data. */
    swap_in(spte->swap_index, spte->upage);
    spte->loaded = true;
    return true;
}

/** Load a page. */
bool load_page(struct sup_page_table_entry *spte)
{
    spte->pinned = true;
    if (spte->loaded)
        return false;

    bool success = false;
    switch (spte->status)
    {

    /** PAGE_FILE and PAGE_MMAP load from a file. */
    case PAGE_FILE:
    case PAGE_MMAP:
        success = load_file(spte);
        break;

    /** PAGE_SWAP loads from swap space. */
    case PAGE_SWAP:
        success = load_swap(spte);
        break;

    /** The status is PAGE_ERROR, can't load. */
    default:
        PANIC("Page status error");
    }
    return success;
}

/** Add a file entry into the current thread's spt. */
bool spt_add_file(struct file *file, off_t ofs, void *upage,
                  uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    /** Create an spte. */
    struct sup_page_table_entry *spte = malloc(sizeof(struct sup_page_table_entry));
    if (spte == NULL)
        return false;

    /** Set status. */
    spte->file = file;
    spte->offset = ofs;
    spte->upage = upage;
    spte->read_bytes = read_bytes;
    spte->zero_bytes = zero_bytes;
    spte->writable = writable;
    spte->loaded = false;
    spte->status = PAGE_FILE;
    spte->pinned = false;

    /** Add to the table. */
    struct sup_page_table *spt = thread_current()->spt;
    lock_acquire(&spt->page_lock);
    bool success = (hash_insert(&spt->page_map, &spte->helem) == NULL);
    if (!success)
        spte->status = PAGE_ERROR;
    lock_release(&spt->page_lock);

    return success;
}

/** Add a mmap entry into the current thread's spt. */
bool spt_add_mmap(struct file *file, off_t ofs, void *upage,
                  uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    /** Create an spte. */
    struct sup_page_table_entry *spte = malloc(sizeof(struct sup_page_table_entry));
    if (spte == NULL)
        return false;

    /** Set status. */
    spte->file = file;
    spte->offset = ofs;
    spte->upage = upage;
    spte->read_bytes = read_bytes;
    spte->zero_bytes = zero_bytes;
    spte->writable = writable;
    spte->loaded = false;
    spte->status = PAGE_MMAP;
    spte->pinned = false;

    /** Add to the mmap list. */
    if (!process_add_mmap(spte))
    {
        free(spte);
        return false;
    }

    /** Add to the table. */
    struct sup_page_table *spt = thread_current()->spt;
    lock_acquire(&spt->page_lock);
    bool success = (hash_insert(&spt->page_map, &spte->helem) == NULL);
    if (!success)
        spte->status = PAGE_ERROR;
    lock_release(&spt->page_lock);

    return success;
}

/** Clear a mmap page and remove its entry from the current thread's spt. */
void spt_remove_mmap(struct sup_page_table_entry *spte)
{
    uint32_t *pd = thread_current()->pagedir;
    spte->pinned = true;
    if (spte->loaded)
    {
        /** Write back. */
        if (pagedir_is_dirty(pd, spte->upage))
        {
            file_lock_acquire();
            file_write_at(spte->file, spte->upage,
                          spte->read_bytes, spte->offset);
            file_lock_release();
        }

        /** Clear the page. */
        frame_free(pagedir_get_page(pd, spte->upage));
        pagedir_clear_page(pd, spte->upage);
    }

    /** Remove its entry. */
    if (spte->status != PAGE_ERROR)
    {
        struct sup_page_table *spt = thread_current()->spt;
        lock_acquire(&spt->page_lock);
        hash_delete(&spt->page_map, &spte->helem);
        lock_release(&spt->page_lock);
    }
}

/** Allocate a new page for the stack. */
bool grow_stack(void *uaddr)
{
    /** Find the address where stack grows. */
    void *upage = pg_round_down(uaddr);
    if ((size_t)(PHYS_BASE - upage) > MAX_STACK_SIZE || !is_user_vaddr(upage))
    {
        return false;
    }

    /** Create spte for the page, the status is PAGE_SWAP
     * because stack page goes to swap space. */
    struct sup_page_table_entry *spte = malloc(sizeof(struct sup_page_table_entry));
    if (spte == NULL)
        return false;

    spte->upage = pg_round_down(uaddr);
    spte->loaded = true;
    spte->writable = true;
    spte->status = PAGE_SWAP;
    spte->pinned = true;

    /** Allocate a frame. */
    uint8_t *frame = frame_alloc(PAL_USER, spte);
    if (!frame)
    {
        free(spte);
        return false;
    }

    /** Install the page. */
    if (!install_page(spte->upage, frame, spte->writable))
    {
        free(spte);
        frame_free(frame);
        return false;
    }

    /** Unpin the page when ready. */
    if (intr_context())
    {
        spte->pinned = false;
    }

    /** Add to the table. */
    struct sup_page_table *spt = thread_current()->spt;
    lock_acquire(&spt->page_lock);
    bool success = (hash_insert(&spt->page_map, &spte->helem) == NULL);
    if (!success)
        spte->status = PAGE_ERROR;
    lock_release(&spt->page_lock);

    return success;
}

/** SPTE hash function. */
static unsigned spte_hash(const struct hash_elem *e,
                          void *aux UNUSED)
{
    struct sup_page_table_entry *spte = hash_entry(e, struct sup_page_table_entry, helem);
    return hash_int((int)spte->upage);
}

/** SPTE destroy function. */
static bool spte_less(const struct hash_elem *a,
                      const struct hash_elem *b,
                      void *aux UNUSED)
{
    struct sup_page_table_entry *ea = hash_entry(a, struct sup_page_table_entry, helem);
    struct sup_page_table_entry *eb = hash_entry(b, struct sup_page_table_entry, helem);
    return ea->upage < eb->upage;
}

/** SPTE destroy function. */
static void spte_destroy(struct hash_elem *e,
                         void *aux UNUSED)
{
    struct sup_page_table_entry *spte = hash_entry(e, struct sup_page_table_entry, helem);
    if (spte->loaded)
    {
        frame_free(pagedir_get_page(thread_current()->pagedir, spte->upage));
        pagedir_clear_page(thread_current()->pagedir, spte->upage);
    }
    free(spte);
}