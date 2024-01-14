#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include <stdbool.h>
#include <stdint.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "vm/page.h"

/** A frame table entry. */
struct frame_table_entry
{
    void *kpage;                       /**< Physical address of the page. */
    struct sup_page_table_entry *spte; /**< Supplyment page table entry. */
    struct thread *owner;              /**< The owner thread of the frame. */
    struct list_elem lelem;            /**< List element. */
};

void frame_init(void);
void *frame_alloc(enum palloc_flags, struct sup_page_table_entry *);
void frame_free(void *);

#endif