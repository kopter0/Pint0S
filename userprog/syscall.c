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

int open_files = 0;
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
	// TODO: Your implementation goes here.
	printf ("system call number %lld!\n", f->R.rax);

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
		printf("NOT implemented %lld\n", f->R.rax);
		break;
	}

	// thread_exit ();
}

void
halt (void) {
	printf("SYSCALL_HALT\n");
	power_off();
}

void 
exit (int status) {
	printf("SYSCALL_EXIT\n");	
	thread_exit();
}

// pid_t
// fork (const char *thread_name){

// }

int
exec (const char *file UNUSED) {
	printf("SYSCALL_EXEC\n");
	return -1;
}

// int wait (pid_t) {
// 	printf("SYSCALL_WAIT\n");
// }

bool 
create (const char *file UNUSED, unsigned initial_size UNUSED) {
	printf("SYSCALL_CREATE\n");
	int result = filesys_create(file, initial_size);
	if (result == 1){
		return true;
	}
	return false;
}

bool
remove (const char *file UNUSED){
	printf("SYSCALL_REMOVE\n");
	int result = filesys_remove(file);
	if (result == 1){
		return true;
	}
	return false;
}

int
open (const char *file UNUSED) {
	printf("SYSCALL_OPEN\n");
	//filesys_open(file);
	return -1;
}

int filesize (int fd UNUSED) {
	printf("SYSCALL_FILESIZE\n");
	return -1;
}

int read (int fd UNUSED, void *buffer UNUSED, unsigned length UNUSED){
	printf("SYSCALL_READ\n");
	return -1;
}

int write (int fd UNUSED, const void *buffer UNUSED, unsigned length UNUSED){
	char *f_name = thread_current() -> name;
	printf("SYSCALL_WRITE with fd: %d, from %s\n", fd, f_name);
	struct file *f;
	if (fd == 1) {
		putbuf((char*)buffer, (size_t)length);
		return length;	
	}
	else {
		f = filesys_open(&f_name);
	}
	if (f) {
		int wrote = file_write(f, buffer, length);
		printf("file opened and %d wrote\n", wrote);
		return wrote;
	}
	else {
		printf("file doesnot exist\n");
		return -1;
	}
}

void seek (int fd UNUSED, unsigned position UNUSED) {
	printf("SYSCALL_SEEK\n");
}

unsigned tell (int fd UNUSED) {
	printf("SYSCALL_TELL\n");
	return 0;
}

void close (int fd UNUSED) {
	printf("SYSCALL_CLOSE\n");
}