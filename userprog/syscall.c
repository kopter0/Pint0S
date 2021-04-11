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

#include "threads/vaddr.h"

#define DEBUG

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void halt (void);
void exit (int status);
// pid_t fork (const char *thread_name);
int exec (const char *file);
// int wait (pid_t);
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
int get_new_fd();

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
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {

	debug_msg("system call number %lld!\n", f->R.rax);

	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	
	case SYS_EXIT:
		exit((int)f->R.rdi);
		break;

	// case SYS_FORK:
		
	// 	break;
	
	case SYS_EXEC:
		f->R.rax = (uint64_t) exec((char *)f->R.rax);
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
exit (int status) {
	debug_msg("SYSCALL_EXIT\n");	
	thread_exit();
}

// pid_t
// fork (const char *thread_name){

// }

int
exec (const char *file UNUSED) {
	debug_msg("SYSCALL_EXEC\n");
	return -1;
}

// int wait (pid_t) {
// 	printf("SYSCALL_WAIT\n");
// }

bool 
create (const char *file UNUSED, unsigned initial_size UNUSED) {
	debug_msg("SYSCALL_CREATE\n");
	return filesys_create(file, initial_size);
}

bool
remove (const char *file UNUSED){
	debug_msg("SYSCALL_REMOVE\n");
	return filesys_remove(file);
}

int
open (const char *file UNUSED) {
	debug_msg("SYSCALL_OPEN\n");
	struct file *f = filesys_open(file);

	return get_new_fd(file);

	return -1;
}

int filesize (int fd UNUSED) {
	debug_msg("SYSCALL_FILESIZE\n");

	return file_length(get_file_by_fd(fd));
	
	// return -1;
}

int read (int fd UNUSED, void *buffer UNUSED, unsigned length UNUSED){
	debug_msg("SYSCALL_READ\n");

	if (fd == 0){
		char *char_buffer = buffer;
		for (int i = 0; i < length; i++){
			char_buffer[i] = input_getc();
		}
		return length;
	}

	struct file *f = get_file_by_fd(fd);
	if (!f) {
		return -1;
	}

	return file_read(f, buffer, length);

	// return -1;
}

int write (int fd UNUSED, const void *buffer UNUSED, unsigned length UNUSED){
	char *f_name = thread_current() -> name;
	debug_msg("SYSCALL_WRITE with fd: %d, from %s\n", fd, f_name);
	
	if (fd == 1) {
		putbuf((char*)buffer, (size_t)length);
		return length;	
	}
	struct file *f = get_file_by_fd(fd);
	if (!f)
		return -1;

	return file_write(f, buffer, length);

	// return -1;
}

void seek (int fd UNUSED, unsigned position UNUSED) {
	debug_msg("SYSCALL_SEEK\n");

	struct file *f = get_file_by_fd(fd);
	if (!f)
		return -1;

	file_seek(f, position);

}

unsigned tell (int fd UNUSED) {
	debug_msg("SYSCALL_TELL\n");

	struct file *f = get_file_by_fd(fd);
	if (!f)
		return -1;

	return file_tell(f);

	// return 0;
}

void close (int fd UNUSED) {
	debug_msg("SYSCALL_CLOSE\n");

	struct file *f = get_file_by_fd(fd);
	if (!f)
		return -1;

	file_close(f);

}

struct file * get_file_by_fd(int fd){
	
} 

int get_new_fd(){

}

int
debug_msg (const char *format, ...) {
	#ifdef DEBUG
	va_list args;
	int retval;

	va_start (args, format);
	retval = vprintf (format, args);
	va_end (args);

	return retval;
	#else
	return 0;
	#endif
	
}