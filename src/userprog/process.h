#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <list.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

/** It is confusing that an error occurs without these typedef. */
typedef int pid_t;
typedef int tid_t;

/** A opened file. */
struct open_file
{
    int fd;                /* File descriptor. */
    struct file *fp;       /* File pointer. */
    struct list_elem elem; /* List element. */
};

/** A mmap file. Different mmap_file can have the same mapid,
 * since the size of a file can be more than 1 page. */
struct mmap_file
{
    int mapid;                         /**< Mmap id. */
    struct sup_page_table_entry *spte; /**< Page table entry. */
    struct list_elem elem;             /**< List element. */
};

/** A user process, I copy most of the code from thread.c,
 * since in my implement a process is actually a thread. */
struct process
{
    pid_t pid;             /**< Process identifier. */
    struct thread *thread; /**< Pointer to thread. */
    bool load_success;     /**< Whether successfully load file. */
    int exit_status;       /**< Process exit code. */

    struct list child;      /**< List of child process. */
    bool child_exited;      /**< If the parent needs to free the child. */
    bool parent_exited;     /**< If the parent process exited. */
    struct process *parent; /**< Parent process. */

    struct semaphore sema_exec; /**< Block parent while executing. */
    struct semaphore sema_wait; /**< Block parent while waiting. */

    struct list_elem allelem; /**< List element for all processes list. */
    struct list_elem elem;    /**< List element. */

    int fd;            /**< Max fd of the process. */
    struct list files; /**< Files the process opened. */
    struct file *file; /**< File that the process execute. */

    int mapid;         /**< Max mapid of the process. */
    struct list mmaps; /**< Mmap files of the process. */
};

void process_init(void);
tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

struct process *process_create(struct thread *);
void init_process(struct process *);
struct process *get_process(pid_t pid);
struct process *get_child(pid_t pid);

int fileno(struct file *);
struct open_file *fdopen(int, const char *);

bool process_add_mmap(struct sup_page_table_entry *spte);
void process_remove_mmap(int mapping);

/** load() helpers. */
bool install_page(void *upage, void *kpage, bool writable);

#endif /**< userprog/process.h */
