#include <stdbool.h>
#include "vm/swap.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include <bitmap.h>

/** How many sectors does a page have. */
#define SECTOR_NUM (PGSIZE / BLOCK_SECTOR_SIZE)
#define SWAP_FREE (false)
#define SWAP_USED (true)

static struct block *swap_block;
static struct bitmap *swap_avaliable;
static struct lock swap_lock;

static size_t swap_size;

/** Initialize the swap disk. */
void swap_init(void)
{
    swap_block = block_get_role(BLOCK_SWAP);
    if (swap_block == NULL)
    {
        PANIC("Can't initialize swap block");
    }

    swap_size = block_size(swap_block) / SECTOR_NUM;
    swap_avaliable = bitmap_create(swap_size);
    if (swap_avaliable == NULL)
    {
        PANIC("Can't initialize swap bitmap");
    }

    bitmap_set_all(swap_avaliable, SWAP_FREE);
    lock_init(&swap_lock);
}

/** Swap out a frame. */
swap_index_t swap_out(void *page)
{
    ASSERT(swap_block != NULL && swap_avaliable != NULL);

    /** Find a avaliable block .*/
    lock_acquire(&swap_lock);
    swap_index_t swap_index = bitmap_scan_and_flip(swap_avaliable, 0, 1, SWAP_FREE);
    if (swap_index == BITMAP_ERROR)
    {
        PANIC("Swap block is full");
    }

    for (size_t i = 0; i < SECTOR_NUM; ++i)
    {
        block_write(swap_block,
                    swap_index * SECTOR_NUM + i,
                    page + i * BLOCK_SECTOR_SIZE);
    }
    lock_release(&swap_lock);
    return swap_index;
}

/** Swap in a frame. */
void swap_in(swap_index_t swap_index, void *page)
{
    ASSERT(swap_index < swap_size);
    if (swap_block == NULL || swap_avaliable == NULL)
    {
        return;
    }

    /** Check avaliable. */
    lock_acquire(&swap_lock);
    if (bitmap_test(swap_avaliable, swap_index) == SWAP_FREE)
    {
        PANIC("Invalid access to unassigned swap block");
    }
    bitmap_flip(swap_avaliable, swap_index);

    for (size_t i = 0; i < SECTOR_NUM; ++i)
    {
        block_read(swap_block,
                   swap_index * SECTOR_NUM + i,
                   page + i * BLOCK_SECTOR_SIZE);
    }
    lock_release(&swap_lock);

    return;
}
