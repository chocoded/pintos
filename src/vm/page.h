#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <hash.h>
#include "threads/synch.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "vm/swap.h"

#define MAX_STACK_SIZE (size_t)(8 * 1024 * 1024)
#define USER_VADDR_BOTTOM ((void *)0x08048000)

/** The status of the page. */
enum page_status
{
    PAGE_FILE,
    PAGE_SWAP,
    PAGE_MMAP,
    PAGE_ERROR,
};

/** The supplyment page table for each thread. */
struct sup_page_table
{
    struct hash page_map;
    struct lock page_lock;
};

/** A supplyment page table entry. */
struct sup_page_table_entry
{
    void *upage;             /**< Virtual address of the page. */
    enum page_status status; /**< Status of the page. */

    struct file *file;   /**< File to store the page. */
    off_t offset;        /**< Offset of the file. */
    uint32_t read_bytes; /**< Bytes already read. */
    uint32_t zero_bytes; /**< Bytes need to be set 0. */

    swap_index_t swap_index; /**< Swap index of the page, only accessable when status is IN_SWAP.*/

    bool writable; /**< Is the page writable. */
    bool loaded;   /**< Is the page pinned. */
    bool pinned;   /**< Is the page pinned. */

    struct hash_elem helem; /**< Hash element. */
};

struct sup_page_table *spt_create(void);
void spt_destroy(struct sup_page_table *);

bool load_file(struct sup_page_table_entry *);
bool load_swap(struct sup_page_table_entry *);
bool load_page(struct sup_page_table_entry *);

bool spt_add_file(struct file *, off_t, void *,
                  uint32_t, uint32_t, bool);
bool spt_add_mmap(struct file *, off_t, void *,
                  uint32_t, uint32_t, bool);
void spt_remove_mmap(struct sup_page_table_entry *);
bool grow_stack(void *);

struct sup_page_table_entry *spt_lookup(void *);

#endif