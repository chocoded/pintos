#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <inttypes.h>

typedef uint32_t swap_index_t;

void swap_init(void);
swap_index_t swap_out(void *);
void swap_in(swap_index_t, void *);

#endif