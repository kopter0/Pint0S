/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {

}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
static bool lazy_do_mmap(struct page* page, void* aux){
	struct load_segment_info *lsi = aux;	
	debug_msg("LAZY_DO_MMAP: %d\n", lsi->ofs);
	lock_acquire(&file_lock);
	lsi->file =  file_reopen(lsi -> file);
	ASSERT(lsi -> file != NULL);
	file_seek(lsi -> file, lsi -> ofs);	 
	// debug_msg("DEBUG: load_addr 0x%x\n", lsi->upage);
	
	int actual_read = file_read(lsi -> file, page -> frame -> kva, (off_t)lsi -> read_bytes);
	if (actual_read != (int) lsi -> read_bytes){
		PANIC("Couldnt write %d, %d\n",actual_read, lsi -> read_bytes);
		return false;
	}
	file_close(lsi -> file);
	lock_release(&file_lock);

	memset (page -> frame -> kva + lsi -> read_bytes, 0, lsi -> zero_bytes);
	return true;


}

void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	ASSERT(file != NULL);
	debug_msg("%d\n", length);
	int read_bytes = length;
	bool success;
	off_t file_len = file_length(file);
	while (read_bytes > 0){
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		void *aux = calloc((size_t) 1, sizeof(struct load_segment_info));
		struct load_segment_info *lsi = (struct load_segment_info*) aux;
		lsi -> file = file;
		lsi -> filename = thread_current() -> name;
		lsi -> ofs = offset;
		lsi -> upage = addr;
		lsi -> read_bytes = page_read_bytes;
		lsi -> zero_bytes = page_zero_bytes;
		lsi -> is_writable = writable;
		success = vm_alloc_page_with_initializer(VM_FILE, addr, (bool) writable, lazy_do_mmap, aux);
		addr += PGSIZE;
		read_bytes -= page_read_bytes;
		offset += page_read_bytes;
	}

	return (success) ? addr : NULL;

}


/* Do the munmap */
void
do_munmap (void *addr) {
}
