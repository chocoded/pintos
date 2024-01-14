#include "userprog/syscall.h"
#include "lib/stdio.h"
#include "lib/kernel/stdio.h"
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "vm/page.h"

/** The number of the syscall. */
#define MAX_SYSCALL_NUM 15

/** The pointer of the user stack, used for
 * checking whether the address is valid. */
void *_esp;

static void syscall_handler(struct intr_frame *);

/** Helpers. */
static void error_exit(void) NO_RETURN;
void get_args(void *esp, int args[], int arg_num);
static struct sup_page_table_entry *check_valid_ptr(const void *, void *);
static void check_valid_str(const void *, void *);
static void check_valid_buf(void *, size_t, void *, bool);
static void unpin_ptr(void *);
static void unpin_str(void *);
static void unpin_buf(void *, size_t);

/** A syscall function. */
typedef int syscall_function(int, int, int);

/** A syscall struct. */
struct syscall
{
	size_t arg_num;
	syscall_function *func;
};

static int sys_halt(void) NO_RETURN;
static int sys_exit(int status) NO_RETURN;
static int sys_exec(const char *cmd_line);
static int sys_wait(pid_t pid);
static int sys_create(const char *file, unsigned initial_size);
static int sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static int sys_seek(int fd, unsigned position);
static int sys_tell(int fd);
static int sys_close(int fd);
static int sys_mmap(int fd, void *addr);
static int sys_munmap(int mapping);

/** The syscall struct table. */
static struct syscall syscall_table[] = {
	{0, (syscall_function *)sys_halt},
	{1, (syscall_function *)sys_exit},
	{1, (syscall_function *)sys_exec},
	{1, (syscall_function *)sys_wait},
	{2, (syscall_function *)sys_create},
	{1, (syscall_function *)sys_remove},
	{1, (syscall_function *)sys_open},
	{1, (syscall_function *)sys_filesize},
	{3, (syscall_function *)sys_read},
	{3, (syscall_function *)sys_write},
	{2, (syscall_function *)sys_seek},
	{1, (syscall_function *)sys_tell},
	{1, (syscall_function *)sys_close},
	{2, (syscall_function *)sys_mmap},
	{1, (syscall_function *)sys_munmap},
};

/** Initialize syscall. */
void syscall_init(void)
{
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/** Does basic check and then handle the syscall. */
static void
syscall_handler(struct intr_frame *f)
{
	f->eax = -1;
	int args[3];
	_esp = f->esp;
	struct syscall *sc;

	/** Check whether the user stack pointer is valid. */
	check_valid_ptr((const void *)_esp, _esp);
	int syscall_num = *(int *)f->esp;
	if (syscall_num < 0 || syscall_num >= MAX_SYSCALL_NUM)
	{
		error_exit();
	}

	/** Initialize the syscall struct and pass the argument. */
	sc = syscall_table + syscall_num;
	memset(args, 0, sizeof(args));
	get_args(f->esp, args, sc->arg_num);

	f->eax = sc->func(args[0], args[1], args[2]);
}

/** Terminates Pintos by calling shutdown_power_off().
 *
 * It should not and would not return. */
static int sys_halt(void)
{
	shutdown_power_off();
	NOT_REACHED();
}

/** Terminates the current user program, returning status to the kernel.
 *
 * If the process's parent waits for it (see below), this is the status
 * that will be returned.
 *
 * A status of 0 indicates success and nonzero values indicate errors. */
static int sys_exit(int status)
{
	thread_current()->process->exit_status = status;
	thread_exit();
	NOT_REACHED();
}

/** Runs the executable whose name is given in file, passing any given arguments,
 * and returns the new process's pid.
 *
 * If the program cannot load or run for any reason, return pid -1.
 *
 * The parent process cannot return from the exec until it knows
 * whether the child process successfully loaded its executable. */
static int sys_exec(const char *cmd_line)
{
	check_valid_str(cmd_line, _esp);

	file_lock_acquire();
	pid_t pid = process_execute(cmd_line);
	file_lock_release();
	unpin_str((void *)cmd_line);
	return pid;
}

/** Waits for a child process pid and retrieves the child's exit status.
 *
 * If pid is still alive: Wait until it terminates and returns the exit status.
 * If pid did not call exit(), but was terminated by the kernel, wait(pid) returns -1.
 *
 * wait fails and returns -1 immediately if any of the following conditions is true:
 * 1) Pid does not refer to a direct child of the calling process.
 * 2) The process that calls wait has already called wait on pid.*/
static int sys_wait(pid_t pid)
{
	return process_wait(pid);
}

/** Creates a new file called file initially initial_size bytes in size.
 * Returns true if successful, false otherwise. */
static int sys_create(const char *file, unsigned initial_size)
{
	check_valid_str(file, _esp);

	file_lock_acquire();
	bool success = filesys_create(file, initial_size);
	file_lock_release();
	unpin_str((void *)file);
	return success;
}

/** Deletes the file called file. Returns true if successful, false otherwise.
 *
 * Removing an open file does not close it.*/
static int sys_remove(const char *file)
{
	check_valid_str(file, _esp);

	file_lock_acquire();
	bool success = filesys_remove(file);
	file_lock_release();
	unpin_str((void *)file);
	return success;
}

/** Opens the file called file. Returns its fd, or -1 if the file could not be opened.
 *
 * fd 0 and 1 are reserved for the console: fd 0 is standard input, fd 1 is standard output.
 * The open system call will never return either of these file descriptors.
 *
 * Each process has an independent set of fd, which is not inherited by child processes.
 *
 * When a single file is opened more than once, whether by a single process or different processes,
 * each open returns a new file descriptor. Different file descriptors for a single file are closed
 * independently in separate calls to close and they do not share a file position.*/
static int sys_open(const char *file)
{
	check_valid_str(file, _esp);

	file_lock_acquire();
	struct file *fp = filesys_open(file);
	unpin_str((void *)file);

	if (fp == NULL)
	{
		file_lock_release();
		return -1;
	}
	else
	{
		int fd = fileno(fp);
		file_lock_release();
		return fd;
	}
}

/** Returns the size, in bytes, of the file open as fd,
 * or -1 if the fd is invalid. */
static int sys_filesize(int fd)
{
	file_lock_acquire();
	struct open_file *file = fdopen(fd, NULL);

	if (file->fp == NULL)
	{
		file_lock_release();
		return -1;
	}
	else
	{
		int size = file_length(file->fp);
		file_lock_release();
		return size;
	}
}

/** Reads size bytes from the file open as fd into buffer.
 * Returns the number of bytes actually read , or -1 if the file could not be read.
 *
 * Fd 0 reads from the keyboard using input_getc(). */
static int sys_read(int fd, void *buffer, unsigned size)
{
	check_valid_buf(buffer, size, _esp, true);

	if (fd == STDOUT_FILENO)
	{
		error_exit();
	}

	if (fd == STDIN_FILENO)
	{
		unsigned i;
		char *buf = (char *)buffer;
		for (i = 0; i < size; i++)
		{
			if ((buf[i] = input_getc()) == 0)
			{
				break;
			}
		}
		unpin_buf((void *)buffer, size);
		return i;
	}
	else
	{
		file_lock_acquire();
		struct open_file *file = fdopen(fd, NULL);
		if (file == NULL)
		{
			file_lock_release();
			unpin_buf((void *)buffer, size);
			return -1;
		}
		else
		{
			int bytes = file_read(file->fp, (void *)buffer, size);
			file_lock_release();
			unpin_buf((void *)buffer, size);
			return bytes;
		}
	}
}

/** Writes size bytes from buffer to the open file fd. Returns the number
 * of bytes actually written, or 0 if no bytes could be written at all.
 *
 * Fd 1 writes to the console using putbuf(). */
static int sys_write(int fd, const void *buffer, unsigned size)
{
	check_valid_buf((void *)buffer, size, _esp, false);

	if (fd == STDIN_FILENO)
	{
		error_exit();
	}

	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, size);
		unpin_buf((void *)buffer, size);
		return size;
	}
	else
	{
		file_lock_acquire();
		struct open_file *file = fdopen(fd, NULL);
		if (file == NULL)
		{
			file_lock_release();
			unpin_buf((void *)buffer, size);
			return -1;
		}
		else
		{
			int bytes = file_write(file->fp, (const void *)buffer, size);
			file_lock_release();
			unpin_buf((void *)buffer, size);
			return bytes;
		}
	}
}

/** Changes the next byte to be read or written in open file fd to position,
 * expressed in bytes from the beginning of the file.
 *
 * A seek past the current end of a file is not an error. */
static int sys_seek(int fd, unsigned position)
{
	file_lock_acquire();
	struct open_file *file = fdopen(fd, NULL);
	if (file == NULL)
	{
		file_lock_release();
		return -1;
	}
	else
	{
		file_seek(file->fp, position);
		file_lock_release();
		return 0;
	}
}

/** Returns the position of the next byte to be read or written in open file fd,
 * expressed in bytes from the beginning of the file. */
static int sys_tell(int fd)
{
	file_lock_acquire();
	struct open_file *file = fdopen(fd, NULL);
	if (file == NULL)
	{
		file_lock_release();
		return -1;
	}
	else
	{
		off_t ofs = file_tell(file->fp);
		file_lock_release();
		return ofs;
	}
}

/** Closes file descriptor fd.
 *
 * Exiting or terminating a process implicitly closes all its open file descriptors,
 * as if by calling this function for each one. */
static int sys_close(int fd)
{
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
	{
		error_exit();
	}

	file_lock_acquire();
	struct open_file *file = fdopen(fd, NULL);
	if (file == NULL)
	{
		file_lock_release();
		return -1;
	}
	else
	{
		file_close(file->fp);
		list_remove(&file->elem);
		file_lock_release();
		free(file);
		return 0;
	}
}

/** Maps the file open as fd into the process's virtual address space.
 * The entire file is mapped into consecutive virtual pages starting at addr.
 *
 * The mapped page is loaded lazily, and evict the page writes back to the file.
 *
 * The file_reopen function is used to obtain a separate and independent reference
 * file for each of its mappings.
 *
 * If the file's length is not a multiple of PGSIZE, some bytes in the last mapped
 * page stick out beyond the end of the file, which will be set to zero when the
 * page is faulted in from the file system, and will be discarded when writing back.
 *
 * Mmap fails and returns -1 immediately if any of the following conditions is true:
 * 1) The given addr is out of range, or it is not page-aligned.
 * 2) The given fd is 0, 1, or it doesn't exist.
 * 3) The file has length 0.
 * 4) The range of pages mapped overlaps any existing set of mapped pages,
 * including the stack or pages mapped at executable load time. */
static int sys_mmap(int fd, void *addr)
{
	/** Can't map fd 0 and 1. */
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
	{
		return -1;
	}

	/** Check the addr. */
	if (!is_user_vaddr(addr) ||
		addr < USER_VADDR_BOTTOM ||
		pg_ofs(addr) != 0)
	{
		return -1;
	}

	file_lock_acquire();
	struct open_file *file = fdopen(fd, NULL);
	/** Can't map a null file. */
	if (file == NULL)
	{
		file_lock_release();
		return -1;
	}

	struct file *fp = file_reopen(file->fp);
	/** Can't map if the file length is 0. */
	if (fp == NULL || file_length(fp) == 0)
	{
		file_lock_release();
		return -1;
	}

	struct process *cur = thread_current()->process;
	cur->mapid++;
	off_t ofs = 0;
	uint32_t read_bytes = file_length(fp);

	/** The following is the same as function 'load_segment()'. */
	while (read_bytes > 0)
	{
		/* Calculate how to fill this page.
		   We will read PAGE_READ_BYTES bytes from FILE
		   and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/** Can't map if overlap. */
		if (!spt_add_mmap(fp, ofs, addr, page_read_bytes,
						  page_zero_bytes, true))
		{
			file_lock_release();
			process_remove_mmap(cur->mapid);
			return -1;
		}

		read_bytes -= page_read_bytes;
		addr += PGSIZE;
		ofs += PGSIZE;
	}
	file_lock_release();
	return cur->mapid;
}

/** Unmaps the mapping designated by mapping, which must be a mapping ID returned
 * by a previous call to mmap by the same process that has not yet been unmapped.
 *
 * When a mapping is unmapped, whether implicitly or explicitly, all pages written
 * to by the process are written back to the file, and pages not written must not be.
 * The pages are then removed from the process's list of virtual pages.
 *
 * Closing or removing a file does not unmap any of its mappings. Once created, a mapping
 * is valid until munmap is called or the process exits, following the Unix convention.
 * */
static int sys_munmap(int mapping)
{
	if (mapping == -1)
	{
		return -1;
	}
	process_remove_mmap(mapping);
	return 0;
}

/** Exit the thread with exit code -1. */
static void error_exit(void)
{
	thread_current()->process->exit_status = -1;
	thread_exit();
}

/** Check the pointers and pass arguments to the arguments array. */
void get_args(void *esp, int args[], int arg_num)
{
	for (int i = 0; i < arg_num; ++i)
	{
		int *ptr = ((int *)esp) + i + 1;
		check_valid_ptr((const void *)ptr, esp);
		args[i] = *ptr;
	}
}

/** Check whether the given address is valid.*/
static struct sup_page_table_entry *check_valid_ptr(const void *vaddr, void *esp)
{
	int i;
	/** Check 4 bytes of the pointer. */
	for (i = 0; i < 4; i++)
	{
		/** Invalid address, terminate the thread. */
		if (!is_user_vaddr(vaddr + i) || vaddr + i == NULL ||
			vaddr + i < USER_VADDR_BOTTOM)
		{
			error_exit();
		}
	}

	bool success = false;
	/** Look for the spte of the address. */
	struct sup_page_table_entry *spte = spt_lookup((void *)vaddr + i);

	/** Found spte, load the page. */
	if (spte)
	{
		load_page(spte);
		success = spte->loaded;
	}

	/** Not found, try to grow the stack. */
	else if (vaddr + i >= esp - 32)
	{
		success = grow_stack((void *)vaddr + i);
	}

	/** Invalid address, terminate the thread. */
	if (!success)
	{
		error_exit();
	}
	return spte;
}

/** Check whether the given string is valid. */
static void check_valid_str(const void *str, void *esp)
{
	char *s = (char *)str;
	check_valid_ptr(s, esp);
	while (*s != 0)
	{
		s = (char *)(s + 1);
		check_valid_ptr(s, esp);
	}
}

/** Check whether the given buffer is valid. */
static void check_valid_buf(void *buf, size_t size, void *esp, bool write)
{
	for (char *_buf = pg_round_down(buf);
		 _buf <= (char *)buf + size; _buf += PGSIZE)
	{
		struct sup_page_table_entry *spte = check_valid_ptr(_buf, esp);
		if (spte && write)
		{
			if (!spte->writable)
			{
				error_exit();
			}
		}
	}
}

/** Unpin the page of the pointer. */
static void unpin_ptr(void *ptr)
{
	struct sup_page_table_entry *spte = spt_lookup(ptr);
	if (spte)
	{
		spte->pinned = false;
	}
}

/** Unpin pages of the string. */
static void unpin_str(void *str)
{
	char *s = (char *)str;
	unpin_ptr(s);
	while (*s != 0)
	{
		s = (char *)(s + 1);
		unpin_ptr(s);
	}
}

/** Unpin pages of the buffer. */
static void unpin_buf(void *buf, size_t size)
{
	for (char *_buf = pg_round_down(buf);
		 _buf <= (char *)buf + size; _buf += PGSIZE)
	{
		unpin_ptr(_buf);
	}
}