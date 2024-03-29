#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "devices/input.h"
#include "string.h"
// #include "palloc.h"
// #define DEBUG

// int open_files = 0;
void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void halt (void);
void exit (int status);
pid_t fork (const char *thread_name, struct intr_frame *if_);
int exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

int debug_msg(const char *format, ...);
struct file * get_file_by_fd(int fd);
int get_new_fd(struct file *);
void remove_fd(int fd);

void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&file_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	debug_msg("SYSCALL %d from %d \n", f->R.rax, thread_current() -> tid);
	#ifdef VM
		thread_current() -> stack_ptr = f -> rsp;
		debug_msg("SYSCALL %d from %d rsp: 0x%x\n", f->R.rax, thread_current() -> tid,f->rsp );
	#endif 
	
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	
	case SYS_EXIT:
		exit((int)f->R.rdi);
		break;

	case SYS_FORK:
		f ->R.rax = (uint64_t) fork((char *) f -> R.rdi, f);	
		break;
	
	case SYS_EXEC:
		f->R.rax = (uint64_t) exec((char *)f->R.rdi);
		break;

	case SYS_WAIT:
		f->R.rax = (uint64_t) wait((pid_t)f -> R.rdi);
		break;

	case SYS_CREATE:
		f->R.rax = (uint64_t) create((const char*)f->R.rdi, (unsigned int)f->R.rsi);
		break;

	case SYS_REMOVE:
		f->R.rax = (uint64_t) remove((const char*) f->R.rdi);
		break;

	case SYS_OPEN:
		f->R.rax = (uint64_t) open((const char*) f->R.rdi);
		break;

	case SYS_FILESIZE:
		f->R.rax = (uint64_t) filesize((int) f->R.rdi);
		break;

	case SYS_READ:
		f->R.rax = (uint64_t) read((int) f->R.rdi, (void *) f->R.rsi, (unsigned int) f->R.rdx);
		break;

	case SYS_WRITE:
		f->R.rax = (uint64_t) write((int) f->R.rdi, (void *) f->R.rsi, (unsigned int) f->R.rdx);
		break;
	
	case SYS_SEEK:
		seek((int) f->R.rdi, (unsigned int) f->R.rsi);
		break;

	case SYS_TELL:
		f->R.rax = (uint64_t) tell((int) f->R.rdi);
		break;
	
	case SYS_CLOSE:
		close((int) f->R.rdi);
		break;
	case SYS_MMAP:
		f->R.rax = (uint64_t) mmap ((void*) f -> R.rdi, (size_t) f -> R.rsi, (int) f -> R.rdx, (int) f -> R.r10, (off_t) f -> R.r8);
		break;
	case SYS_MUNMAP:
		munmap((void *) f -> R.rdi);
		break;

	default:
		debug_msg("NOT IMPLEMENTED %lld\n", f->R.rax);
		break;
	}

	// thread_exit ();
}

void
halt (void) {
	debug_msg("SYSCALL_HALT\n");
	power_off();
}

void 
exit (int status UNUSED) {
	debug_msg("SYSCALL_EXIT\n");
	// thread_current() -> child_info.child_exit_status = status;
	struct historical_record *hr = find_in_history(thread_current() -> tid);
	hr->exit_status = status;	
	thread_exit();
}
    
pid_t
fork (const char *thread_name, struct intr_frame *if_){
	// tid_t tid = process_fork(thread_name, if_);
	tid_t tid = process_fork(thread_name, if_);
	if (tid == TID_ERROR){
		return -1;
	} 
	// sema_down(&get_thread_by_tid(tid) -> child_info.child_load_sema);
	struct historical_record *hr = find_in_history(tid);
	hr -> parent_tid = thread_current() -> tid;	
	sema_down(&hr -> sema_load);
	return tid;
}

int
exec (const char *file UNUSED) {
	debug_msg("SYSCALL_EXEC\n");
	void *f = pml4_get_page(thread_current() -> pml4, file);
	
	if (!f){
		debug_msg("EXEC: exit 0x%x\n", f);
		exit(-1);
	}
	// return process_exec(f);
	return process_exec(file);
}

int wait (pid_t pid) {
	debug_msg("SYSCALL_WAIT\n");
	return process_wait(pid);
}

bool 
create (const char *file UNUSED, unsigned initial_size UNUSED) {
	debug_msg("SYSCALL_CREATE\n");
	if (!pml4_get_page(thread_current() -> pml4, file)){
		debug_msg("Not in writeble\n");
		exit(-1);
	}
	lock_acquire(&file_lock);
	bool output = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return output;
}

bool
remove (const char *file UNUSED){
	debug_msg("SYSCALL_REMOVE\n");
	lock_acquire(&file_lock);
	bool output = filesys_remove(file);
	lock_release(&file_lock);
	return output;
}

int
open (const char *file UNUSED) {
	debug_msg("SYSCALL_OPEN %s\n", file);
	if (!pml4_get_page(thread_current()->pml4, file)){
		exit(-1);
	} 
 
	lock_acquire(&file_lock);
	struct file *f = filesys_open(file);
	if (strcmp(file, thread_current()->name) == 0){
		file_deny_write(f);
	}
	lock_release(&file_lock);
	if (!f) {
		debug_msg("File could not be opened\n");
		return -1;
	}
	return get_new_fd(f);
}

int filesize (int fd UNUSED) {
	debug_msg("SYSCALL_FILESIZE\n");
	lock_acquire(&file_lock);
	int filesize = (int)file_length(get_file_by_fd(fd));
	lock_release(&file_lock);
	return filesize;
	// return -1;
}

int read (int fd UNUSED, void *buffer UNUSED, unsigned length UNUSED){
	debug_msg("SYSCALL_READ\n");
	
	if (!pml4_get_page(thread_current() -> pml4, buffer)){
		if (!vm_try_handle_fault(&thread_current() -> tf, buffer, true, true, true)){
			debug_msg("Not readable\n");
			exit(-1);
			
		}
	}

	if (fd == 0){
		char *char_buffer = buffer;
		for (int i = 0; i < (signed)length; i++){
			char_buffer[i] = input_getc();
		}
		return length;
	}

	struct file *f = get_file_by_fd(fd);
	if (!f) {
		return -1;
	}
	lock_acquire(&file_lock);
	int read =  file_read(f, buffer, length);
	lock_release(&file_lock);
	return read;

	// return -1;
}

int write (int fd UNUSED, const void *buffer UNUSED, unsigned length UNUSED){
	char *f_name = thread_current() -> name;
	debug_msg("SYSCALL_WRITE with fd: %d, from %s, buffer 0x%x\n", fd, f_name, buffer);
	
	if (!pml4_get_page(thread_current() -> pml4, buffer)){
		debug_msg("Not in writeble\n");
		exit(-1);
	}

	if (fd == 1) {
		putbuf((char*)buffer, (size_t)length);
		return length;	
	}
	struct file *f = get_file_by_fd(fd);
	if (!f){
		debug_msg("File not found\n");
		return -1;
	}
	lock_acquire(&file_lock);
	int write =  file_write(f, buffer, length);
	lock_release(&file_lock);
	return write;

	// return -1;
}

void seek (int fd UNUSED, unsigned position UNUSED) {
	debug_msg("SYSCALL_SEEK\n");
	struct file *f = get_file_by_fd(fd);
	if (!f)
		return;
	lock_acquire(&file_lock);
	file_seek(f, (off_t) position);
	lock_release(&file_lock);
}

unsigned tell (int fd UNUSED) {
	debug_msg("SYSCALL_TELL\n");

	struct file *f = get_file_by_fd(fd);
	if (!f)
		return -1;
	lock_acquire(&file_lock);
	unsigned tell = (unsigned) file_tell(f);
	lock_release(&file_lock);
	return tell;
	// return 0;
}

void close (int fd UNUSED) {
	debug_msg("SYSCALL_CLOSE\n");

	struct file *f = get_file_by_fd(fd);
	if (!f)
		return;
	lock_acquire(&file_lock);
	file_close(f);
	remove_fd(fd);
	lock_release(&file_lock);

}

struct file * get_file_by_fd(int fd){
	struct list_elem *e = list_begin(&thread_current()->file_table);
	for (; e!=list_end(&thread_current()->file_table);e=list_next(e)){
		struct file_table_elem *fte = list_entry(e, struct file_table_elem, element); 
		if (fte -> fd == fd)
			return fte->file;
	}
	return NULL;
} 

int get_new_fd(struct file *f){
	int fd = thread_current()->next_fd++;
	struct file_table_elem *fte = calloc(1, sizeof(struct file_table_elem));
	fte->fd = fd;
	fte->file = f; 
	list_push_back(&thread_current()->file_table, &fte -> element);
	return fd; 
}

void remove_fd(int fd){
	struct list_elem *e = list_begin(&thread_current()->file_table);
	for (; e!=list_end(&thread_current()->file_table);e=list_next(e)){
		struct file_table_elem *fte = list_entry(e, struct file_table_elem, element); 
		if (fte -> fd == fd){
			list_remove(e);
			break;
		}
	} 
}

void *mmap (void *addr, size_t length, int writable, int fd, off_t offset){

	if (fd < 2 || get_file_by_fd(fd) == NULL){
		debug_msg("MMAP fd 1 or 0\n");
		return NULL;
	}
	debug_msg("MMAP kernel vaddr 0x%x\n", addr);
	if (is_kernel_vaddr(addr) || is_kernel_vaddr(addr - length)){
		debug_msg("MMAP kernel vaddr 0x%x\n", addr);
		return NULL;
	}

	if (spt_find_page(&thread_current() -> spt, addr)){
		debug_msg("MMAP addr\n");
		return NULL;
	}

	//debug_msg("MMAP %d", get_file_by_fd(fd) == NULL);

	if (!filesize (fd)){
		debug_msg("MMAP file size 0\n");
		return NULL;
	}
	debug_msg("MMAP offset : %d,  %d\n", pg_ofs(addr), offset);
	if (pg_ofs(addr)){
		debug_msg("MMAP not aligned\n");
		return NULL;
	}

	if (addr == NULL || length == 0){
		debug_msg("MMAP address NULL or len 0\n");
		return NULL;
	}
	//debug_msg("MMAP offset : %d,  %d\n", file_length(get_file_by_fd(fd)), offset);
	if (offset % PGSIZE != 0){
		debug_msg("MMAP offset : %d\n", offset);
		return NULL;
	}

	return do_mmap(addr, length, writable, get_file_by_fd(fd), offset);
	
} 

void munmap (void *addr){
	do_munmap(addr);
}


// int
// debug_msg (const char *format, ...) {
// 	#ifdef DEBUG
// 	va_list args;
// 	int retval;

// 	va_start (args, format);
// 	retval = vprintf (format, args);
// 	va_end (args);

// 	return retval;
// 	#else
// 	return 0;
// 	#endif
	
// }