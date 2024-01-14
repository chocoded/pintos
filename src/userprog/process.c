#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"

#include "vm/frame.h"
#include "vm/page.h"

#ifndef VM
#define frame_alloc(x, y) palloc_get_page(x)
#define frame_free(x) palloc_free_page(x)
#endif

/** The stack pointer can point to anything, the definition can
 * avoid type cast. */
typedef union
{
	void *vp;
	char *cp1;
	char **cp2;
	char ***cp3;
	int *ip;
	unsigned u;
	void (**ret_addr)(void);
} esp_t;

/** List of all processes. Processes are added to this list
   when they are created and removed when they exit. */
static struct list all_list;

/** Lock used for file. */
static struct lock file_lock;

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);
static void *arg_pass(esp_t esp, char *cmd, char *save_ptr);

/** Initializes the process system. */
void process_init(void)
{
	list_init(&all_list);
	lock_init(&file_lock);
}

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name)
{

	char *fn_copy, *my_fn_copy, *real_name, *save_ptr;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	   Otherwise there's a race between the caller and load(). */
	my_fn_copy = palloc_get_page(0);
	if (my_fn_copy == NULL)
	{
		return TID_ERROR;
	}
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
	{
		palloc_free_page(my_fn_copy);
		return TID_ERROR;
	}

	strlcpy(fn_copy, file_name, PGSIZE);
	strlcpy(my_fn_copy, file_name, PGSIZE);
	real_name = strtok_r(my_fn_copy, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create(real_name, PRI_DEFAULT, start_process, fn_copy);

	palloc_free_page(my_fn_copy);
	if (tid == TID_ERROR)
	{
		palloc_free_page(fn_copy);
	}

	/* The initial_thread does not call thread_create(),
	 * so its process pointer is NULL. */
	if (thread_current()->tid != 1 && tid != TID_ERROR)
	{
		struct process *cur = thread_current()->process;
		struct process *child = get_process(tid);
		child->parent = cur;
		list_push_back(&cur->child, &child->elem);

		/* Block the parent process until we really
		 * executing the child process. */
		sema_down(&child->sema_exec);

		if (child->load_success == false)
		{
			sema_down(&child->sema_wait);
			list_remove(&child->allelem);
			list_remove(&child->elem);
			free(child);
			return TID_ERROR;
		}
	}

	return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process(void *file_name_)
{
	char *file_name = file_name_;
	char *cmd, *save_ptr;
	struct intr_frame if_;
	bool success;

	/* Initialize interrupt frame and load executable. */
	memset(&if_, 0, sizeof if_);
	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
	if_.cs = SEL_UCSEG;
	if_.eflags = FLAG_IF | FLAG_MBS;

	cmd = strtok_r(file_name, " ", &save_ptr);
	success = load(cmd, &if_.eip, &if_.esp);

	struct process *cur = thread_current()->process;
	cur->load_success = success;

	/* If load succeeded, push arguments and call file_deny_write.
	 * Then call sema_up to unblock the parent process. */
	if (success)
	{
		if_.esp = arg_pass((esp_t)if_.esp, cmd, save_ptr);
		cur->file = filesys_open(cmd);
		file_deny_write(cur->file);
		sema_up(&cur->sema_exec);
	}

	/* If load failed, sema_up to unblock the parent process and quit. */
	palloc_free_page(file_name);
	if (!success)
	{
		sema_up(&cur->sema_exec);
		thread_exit();
		NOT_REACHED();
	}

	/* Start the user process by simulating a return from an
	   interrupt, implemented by intr_exit (in
	   threads/intr-stubs.S).  Because intr_exit takes all of its
	   arguments on the stack in the form of a `struct intr_frame',
	   we just point the stack pointer (%esp) to our stack frame
	   and jump to it. */
	asm volatile("movl %0, %%esp; jmp intr_exit"
				 :
				 : "g"(&if_)
				 : "memory");
	NOT_REACHED();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_tid)
{
	/** The process pointer of initial_thread is NULL. Use all_list
	 * since every process is its child.
	 *
	 * The invalid TID will return NULL in get function below.
	 */
	bool is_init_thread = thread_current()->tid == 1;
	struct process *child = is_init_thread ? get_process(child_tid)
										   : get_child(child_tid);

	if (child == NULL)
		return -1;

	/* Block the parent process until child process exits . */
	sema_down(&child->sema_wait);

	/* The child process finished, it's no longer the child of its parent.
	 * We remove it from the list, set exit code and free the memory. */
	if (!is_init_thread)
		list_remove(&child->elem);
	list_remove(&child->allelem);
	int exit_status = child->exit_status;
	free(child);

	return exit_status;
}

/** Free the current process's resources. */
void process_exit(void)
{
	struct thread *cur = thread_current();
	uint32_t *pd;

	printf("%s: exit(%d)\n", cur->name, cur->process->exit_status);

#ifdef VM
	process_remove_mmap(-1);
	spt_destroy(cur->spt);
	cur->spt = NULL;
#endif

	/* Destroy the current process's page directory and switch back
	   to the kernel-only page directory. */
	pd = cur->pagedir;
	if (pd != NULL)
	{
		/* Correct ordering here is crucial.  We must set
		   cur->pagedir to NULL before switching page directories,
		   so that a timer interrupt can't switch back to the
		   process page directory.  We must activate the base page
		   directory before destroying the process's page
		   directory, or our active page directory will be one
		   that's been freed (and cleared). */

		cur->pagedir = NULL;
		pagedir_activate(NULL);
		pagedir_destroy(pd);
	}

	struct process *p = cur->process;

	/** Close opened files. */
	while (!list_empty(&p->files))
	{
		struct open_file *file = list_entry(list_back(&p->files),
											struct open_file, elem);
		file_close(file->fp);
		list_remove(&file->elem);
		free(file);
	}

	/** Allow write and close itself. */
	if (p->file)
	{
		file_allow_write(p->file);
		file_close(p->file);
	}

	/** Set child's parent state. */
	for (struct list_elem *e = list_begin(&p->child);
		 e != list_end(&p->child); e = list_next(e))
	{
		struct process *child = list_entry(e, struct process, elem);
		child->parent_exited = true;

		if (child->child_exited)
		{
			list_remove(&child->allelem);
			list_remove(&child->elem);
			free(child);
		}
	}

	/** We don't free process here, since we still have to use its exit code.*/
	if (p->parent_exited == false)
	{
		p->child_exited = true;
		sema_up(&p->sema_wait);
	}

	/** The parent already exited, free the resources here. */
	else
	{
		list_remove(&p->allelem);
		list_remove(&p->elem);
		free(p);
	}
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
	struct thread *t = thread_current();

	/* Activate thread's page tables. */
	pagedir_activate(t->pagedir);

	/* Set thread's kernel stack for use in processing
	   interrupts. */
	tss_update();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32 /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
	unsigned char e_ident[16];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
};

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
	Elf32_Word p_type;
	Elf32_Off p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
};

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0			/**< Ignore. */
#define PT_LOAD 1			/**< Loadable segment. */
#define PT_DYNAMIC 2		/**< Dynamic linking info. */
#define PT_INTERP 3			/**< Name of dynamic loader. */
#define PT_NOTE 4			/**< Auxiliary info. */
#define PT_SHLIB 5			/**< Reserved. */
#define PT_PHDR 6			/**< Program header table. */
#define PT_STACK 0x6474e551 /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /**< Executable. */
#define PF_W 2 /**< Writable. */
#define PF_R 4 /**< Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes,
						 bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp)
{
	struct thread *t = thread_current();
	struct Elf32_Ehdr ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pagedir = pagedir_create();

#ifdef VM
	/** Create the supplyment page table for current thread. */
	t->spt = spt_create();
#endif

	if (t->pagedir == NULL)
		goto done;
	process_activate();

	/* Open executable file. */
	file = filesys_open(file_name);
	if (file == NULL)
	{
		printf("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
	{
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Elf32_Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* Ignore this segment. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint32_t file_page = phdr.p_offset & ~PGMASK;
				uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint32_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
					   Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					/* Entirely zero.
					   Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment(file, file_page, (void *)mem_page,
								  read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack(esp))
		goto done;

	/* Start address. */
	*eip = (void (*)(void))ehdr.e_entry;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close(file);
	return success;
}

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (Elf32_Off)file_length(file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

		- READ_BYTES bytes at UPAGE must be read from FILE
		  starting at offset OFS.

		- ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Calculate how to fill this page.
		   We will read PAGE_READ_BYTES bytes from FILE
		   and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

#ifdef VM
		/** Lazy loading. */
		if (!spt_add_file(file, ofs, upage, page_read_bytes,
						  page_zero_bytes, writable))
		{
			return false;
		}
#else
		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page(upage, kpage, writable))
		{
			palloc_free_page(kpage);
			return false;
		}
#endif
		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;

#ifdef VM
		ofs += PGSIZE;
#endif
	}
	return true;
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp)
{
#ifndef VM
	uint8_t *kpage;
	bool success = false;

	/** Changed to frame allocation. */
	kpage = frame_alloc(PAL_USER | PAL_ZERO, ((uint8_t *)PHYS_BASE) - PGSIZE);
	if (kpage != NULL)
	{
		success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
		if (success)
			*esp = PHYS_BASE;
		else
			frame_free(kpage);
	}
	return success;
#else
	bool success = grow_stack(((uint8_t *)PHYS_BASE) - PGSIZE);
	if (success)
		*esp = PHYS_BASE;
	return success;
#endif
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* Verify that there's not already a page at that virtual
	   address, then map our page there. */
	bool success = (pagedir_get_page(t->pagedir, upage) == NULL &&
					pagedir_set_page(t->pagedir, upage, kpage, writable));
	return success;
}

/** Argument passing. I get the idea of this from shell-lab in ICS. */
static void *arg_pass(esp_t esp, char *cmd, char *save_ptr)
{
	char *argv[256];
	int i = 0, argc, size;
	/* Push arguments. */
	for (char *ptr = cmd; ptr; ptr = strtok_r(NULL, " ", &save_ptr))
	{
		size = strlen(ptr) + 1;
		esp.cp1 -= size;
		strlcpy(esp.cp1, ptr, size);
		argv[i++] = esp.cp1;
	}
	argc = i;
	argv[i++] = NULL;

	/* Push word-align. */
	esp.u &= -4;

	/* Push argument pointers(argv[i]) */
	esp.cp2 -= i;
	memcpy(esp.cp2, argv, i * sizeof(char *));

	/* Push argv. */
	char **argv_ptr = esp.cp2;
	*(--esp.cp3) = argv_ptr;

	/* Push argc. */
	*(--esp.ip) = argc;

	/* Push fake return address. */
	*(--esp.ret_addr) = NULL;

	return esp.vp;
}

/** Creates a new process with the given thread t and
 * adds it to all_list(child list of initial_thread).
 * Returns the pointer to the new process, or NULL if creation fails.*/
struct process *process_create(struct thread *t)
{
	struct process *p = malloc(sizeof(struct process));
	if (p == NULL)
		return p;

	p->thread = t;
	init_process(p);

	return p;
}

/** Does basic initialization of the process. */
void init_process(struct process *p)
{

	p->pid = p->thread->tid;
	p->exit_status = -1;

	/** Initialize semaphore. */
	sema_init(&p->sema_exec, 0);
	sema_init(&p->sema_wait, 0);

	/** Initialize child processes. */
	p->parent_exited = false;
	p->child_exited = false;
	p->parent = NULL;
	list_init(&p->child);

	/** Initialize open files. */
	p->fd = 2;
	list_init(&p->files);
	p->file = NULL;

	/** Initialize mapps .*/
	p->mapid = 0;
	list_init(&p->mmaps);

	list_push_back(&all_list, &p->allelem);
}

/** Get the process in the all_list by the given pid. */
struct process *get_process(pid_t pid)
{
	ASSERT(pid != TID_ERROR);

	for (struct list_elem *e = list_begin(&all_list);
		 e != list_end(&all_list); e = list_next(e))
	{
		struct process *p = list_entry(e, struct process, allelem);
		if (p->pid == pid)
		{
			return p;
		}
	}

	return NULL;
}

/** Get the child process by the given pid. Return NULL if not found. */
struct process *get_child(pid_t pid)
{
	ASSERT(pid != TID_ERROR);

	struct list *l = &thread_current()->process->child;
	for (struct list_elem *e = list_begin(l); e != list_end(l); e = list_next(e))
	{
		struct process *p = list_entry(e, struct process, elem);
		if (p->pid == pid)
		{
			return p;
		}
	}

	return NULL;
}

/** Get file descriptor by file pointer. */
int fileno(struct file *fp)
{
	ASSERT(fp != NULL);

	struct process *cur = thread_current()->process;
	struct open_file *file = malloc(sizeof(struct open_file));

	file->fd = cur->fd++;
	file->fp = fp;
	list_push_back(&cur->files, &file->elem);

	return file->fd;
}

/** Get file pointer by file descriptor. Return NULL if not found.
 *  Maybe implement the open mode in the future. */
struct open_file *fdopen(int fd, const char *mode UNUSED)
{
	struct process *cur = thread_current()->process;

	for (struct list_elem *e = list_begin(&cur->files);
		 e != list_end(&cur->files); e = list_next(e))
	{
		struct open_file *file = list_entry(e, struct open_file, elem);
		if (file->fd == fd)
		{
			return file;
		}
	}

	return NULL;
}

/** Add a mmap file into the current process. */
bool process_add_mmap(struct sup_page_table_entry *spte)
{
	struct process *cur = thread_current()->process;
	struct mmap_file *mm = malloc(sizeof(struct mmap_file));
	if (mm == NULL)
		return false;

	mm->mapid = cur->mapid;
	mm->spte = spte;
	list_push_back(&cur->mmaps, &mm->elem);

	return true;
}

/** Remove a mmap from the current process.
 * if the mapping is -1, remove all. */
void process_remove_mmap(int mapping)
{
	struct process *cur = thread_current()->process;
	struct list_elem *next, *e = list_begin(&cur->mmaps);
	struct file *file = NULL;
	int close = 0;

	while (e != list_end(&cur->mmaps))
	{
		next = list_next(e);
		struct mmap_file *mm = list_entry(e, struct mmap_file, elem);
		/** Find the mmap files. */
		if (mm->mapid == mapping || mapping == -1)
		{
			/** Clear the page and remove its entry. */
			spt_remove_mmap(mm->spte);

			/** Remove from process mmap list. */
			list_remove(&mm->elem);

			/** Close mmap file. */
			if (mm->mapid != close)
			{
				if (file)
				{
					file_lock_acquire();
					file_close(file);
					file_lock_release();
				}
				close = mm->mapid;
				file = mm->spte->file;
			}
			free(mm->spte);
			free(mm);
		}
		e = next;
	}

	/** Close mmap file. */
	if (file)
	{
		file_lock_acquire();
		file_close(file);
		file_lock_release();
	}
}

/** Acquire the file lock while using file system. */
void file_lock_acquire(void)
{
	lock_acquire(&file_lock);
}

/** Release the file lock after using file system. */
void file_lock_release(void)
{
	lock_release(&file_lock);
}