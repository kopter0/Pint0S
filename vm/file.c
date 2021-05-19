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
	file_page ->file = NULL;
	page->spt_entry=NULL;
	
}

/* Do the mmap */
static bool lazy_do_mmap(struct page* page, void* aux){
	struct load_segment_info *lsi = aux;	
	debug_msg("LAZY_DO_MMAP: %d\n", lsi->ofs);
	lock_acquire(&file_lock);
	// lsi->file =  file_reopen(lsi -> file);
	debug_msg("size %d\n", file_length(lsi->file));
	ASSERT(lsi -> file != NULL);
	file_seek(lsi -> file, lsi -> ofs);	 
	int actual_read = file_read(lsi -> file, page -> frame -> kva, (off_t)lsi -> read_bytes);
	if (actual_read != (int) lsi -> read_bytes){
		PANIC("Couldnt write %d, %d\n",actual_read, lsi -> read_bytes);
		return false;
	}
	// file_close(lsi -> file);
	lock_release(&file_lock);

	page->file.file = lsi->file;
	page->file.length = lsi->read_bytes;
	page->file.offset = lsi->ofs;

	memset (page -> frame -> kva + lsi -> read_bytes, 0, lsi -> zero_bytes);
	return true;


}

void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	ASSERT(file != NULL);
	void *init_addr = addr;
	int read_bytes = length;
	bool success;
	off_t remained_len = file_length(file);

	while (read_bytes > 0 && remained_len > 0){
		size_t should_read = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_read_bytes = remained_len < read_bytes ? remained_len : read_bytes;
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
		remained_len -= page_read_bytes;
	}


	return init_addr;
}


/* Do the munmap */
void
do_munmap (void *addr) {
	struct page *page = spt_find_page(&thread_current() -> spt, addr);
	if (page_get_type(page) != VM_FILE){
		PANIC("not VM_FILE");
	}
	lock_acquire(&file_lock);
	struct file *file = page -> file.file;
	
	void *init_addr = addr;
	off_t length = file_length(file);
	while (init_addr < addr + file_length(file)){
		struct page *pg = spt_find_page(&thread_current() -> spt, init_addr);
		if (page_get_type(pg) != VM_FILE){
			PANIC("not VM_FILE");
		}
		file_seek(file, pg -> file.offset);
		off_t size = (pg -> file.length < PGSIZE) ? pg -> file.length : PGSIZE; 
		off_t bytes_written = file_write (file, pg -> frame -> kva, size);
		if (bytes_written < pg -> file.length){
			debug_msg("DEBUG: bytes_written: %d, page file len: %d \n", bytes_written, pg -> file.length);
		}
		init_addr += bytes_written;
		spt_remove_page (&thread_current() -> spt, pg);
	}
	//file_close(file);
	lock_release(&file_lock);

}
