/* vm.c: Generic interface for virtual memory objects. */

#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
#include "devices/input.h"
#include "string.h"
#include "vm/uninit.h"
#include <stdio.h>
#define STACK_LIMIT (1024 * 1024 * 8) 
#define USER_STACK_LIMIT 0x47380000


/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;


	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
			struct page *new_page = (struct page*)malloc(sizeof(struct page));
			bool *initializer;
			switch (VM_TYPE(type))
			{
			case VM_ANON:
				initializer = &anon_initializer;
				break;
			case VM_FILE:
				initializer = &file_backed_initializer;
				break;
			/*TO_DO: VM_PAGE_CACHE*/
			default:
				initializer = &anon_initializer;
				//PANIC("no match vm_type");
				break;
			}
			
			uninit_new(new_page, upage ,init, type, aux, initializer);
			new_page -> writable = writable;
		/* TODO: Insert the page into the spt. */
		bool insert_succ = spt_insert_page(spt, new_page);
		
		return insert_succ;
	}
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */

	if (hash_empty(spt -> page_table))
		return NULL;

	struct spt_entry se;
	struct hash_elem *e;
	se.vaddr = va;
	lock_acquire(&spt -> lock);
	e = hash_find(spt->page_table, &se.elem);
	lock_release(&spt->lock);
	page = e != NULL ? hash_entry(e, struct spt_entry, elem) -> pg : NULL; 

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	struct spt_entry* new_entry = (struct spt_entry*) calloc(sizeof(struct spt_entry), 1);
	new_entry -> pg = page;
	new_entry -> vaddr = page -> va;
	new_entry -> is_writable = page -> writable;
	new_entry -> last_access = 0;
	new_entry -> t = thread_current();
	page -> spt_entry = new_entry;
	lock_acquire(&spt->lock);
	hash_insert(spt -> page_table, &new_entry -> elem);
	lock_release(&spt->lock);
	succ = true;
	
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	struct spt_entry se;
	se.vaddr = page->va;
	struct hash_elem *e = hash_delete(spt->page_table, &se.elem);
	struct spt_entry *spte = hash_entry(e, struct spt_entry, elem);
	spte->pg = NULL;
	spte->paddr = NULL;
	free(spte);
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */


// bool is_swapped_out (struct spt_entry* se){
// 	switch (VM_TYPE(se -> vm_type)) {
// 		case VM_ANON:
// 			return se -> pg -> anon.swapped_out;
// 		default:
// 			return true;
// 	}
// }

static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	

	struct thread* t = thread_current();
	struct hash_iterator i;

	hash_first (&i, t -> spt.page_table);
	struct spt_entry *to_evict;
	uint64_t biggest_val = 0;
	while (hash_next (&i))
	{
		struct spt_entry *ste = hash_entry (hash_cur (&i), struct spt_entry, elem);
		if (!is_swapped_out(ste) && ste -> last_access > biggest_val){
			biggest_val = ste->last_access;
			to_evict = ste;
			if (biggest_val > 50)
				break;
		}
	}

	// printf("evicting 0x%x, la: %d, type: %d\n", to_evict -> vaddr, to_evict -> last_access, to_evict -> vm_type);
	to_evict->pg->anon.swapped_out = true;
	return to_evict->pg->frame;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim ->page);
	pml4_clear_page(thread_current() -> pml4, victim -> page -> va);
	victim -> page = NULL;
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = (struct frame *) calloc((size_t) 1, sizeof(struct frame));
	/* TODO: Fill this function. */
	frame -> kva = palloc_get_page(PAL_USER);

	if (frame -> kva == NULL) {
		frame = vm_evict_frame();
	}

	ASSERT (frame != NULL);
	ASSERT (frame -> kva != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	bool succ;
	void *addr_rounded = pg_round_down(addr);
	debug_msg("DEBUG: addr_rounded: 0x%x, 0x%x\n", addr_rounded, thread_current() -> stack_ptr);
	while (thread_current() -> stack_ptr - PGSIZE > addr_rounded){
		debug_msg("Claiming 0x%x\n", addr_rounded);
		vm_alloc_page(VM_ANON + VM_MARKER_0, addr_rounded, true);
		succ &= vm_claim_page(addr_rounded);
		addr_rounded += PGSIZE;
	}
	succ = true;
	thread_current() -> tf.rsp = addr;
	if (succ == false)
		PANIC("stack growth failed");
	//debug_msg("DEBUG stack growth 0x%x\n", pml4_get_page(thread_current() -> pml4, addr));
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = spt_find_page(spt ,pg_round_down(addr));
	bool success = true;
	debug_msg("HANDLING FAULT: addr: 0x%x, user: %d write:%d not_present:%d\n", addr, user, write, not_present);
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (!not_present){
		return false;
	}
	if (page == NULL) {
		uintptr_t rsp;
		if (write){
			if (user){
					rsp = thread_current() -> stack_ptr;
			}else{
				rsp = thread_current() -> stack_ptr;
			}


			debug_msg("HANDLING FAULT: FADDR: %p, RSP: 0x%x, lim: 0x%x, 0x%x\n", addr, rsp);
		    if ((addr != NULL) && (addr <= rsp ) && (addr < KERN_BASE) && (addr > USER_STACK_LIMIT)){
			// if (KERN_BASE - STACK_LIMIT < addr && addr <= KERN_BASE) {
      		// 	if (addr == rsp - 4 || addr == rsp - 32 || addr >= rsp) {
					vm_stack_growth(addr);
					debug_msg("DEBUG stack growth %d\n",rsp - (uintptr_t) pg_round_down(addr));
				
			}else {
				debug_msg("DEBUG: not a stack\n");
				return false;
				// PANIC("LIMIT exceeded");
			}
		}else{
			success = false;
		}
		 
	}else{
		success = vm_do_claim_page (page);
	}

	return success;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	// struct page *page = (struct page*) calloc((size_t) 1, sizeof(struct page));
	struct page *page = spt_find_page(&thread_current() -> spt, va);
	if (page == NULL)
		PANIC("no page 0x%x", va);

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();	
	
	/* Set links */
	frame->page = page;
	page->frame = frame;
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	page -> spt_entry -> paddr = frame -> kva;
	
	bool succ = pml4_set_page(thread_current() -> pml4, page -> va, frame -> kva, page ->spt_entry ->is_writable);
	ASSERT (succ);

	page -> spt_entry -> vm_type = page_get_type(page);
	debug_msg("DEBUG: do_claim_page %p, %p %d\n", page -> va, frame -> kva, page -> spt_entry -> vm_type);
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	spt -> page_table = calloc((size_t) 1, sizeof(struct hash));
	bool result = hash_init(spt -> page_table, &page_hash, &page_less, NULL);
	lock_init(&spt -> lock);
	spt -> thread = thread_current();
	spt -> inited = true;
}

bool copy_init (struct page *pg, void *aux){
	struct page *srcpg = aux;
	memcpy(pg -> frame -> kva, srcpg -> frame -> kva, (size_t)PGSIZE);

	return true;
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	lock_acquire(&src -> lock);
	struct hash_iterator j;

   	hash_first (&j, src -> page_table);
  while (hash_next (&j)){
		struct spt_entry *src_spt_entry = hash_entry (hash_cur (&j), struct spt_entry, elem);
		debug_msg("copy 0x%x %d\n", src_spt_entry -> vaddr, VM_TYPE(src_spt_entry ->vm_type));
		switch (VM_TYPE(src_spt_entry -> vm_type))
		{
		case VM_UNINIT:
			vm_alloc_page_with_initializer(page_get_type(src_spt_entry->pg), 
																	src_spt_entry -> vaddr, 
																	src_spt_entry -> is_writable, 
																	src_spt_entry -> pg -> uninit.init, 
																	src_spt_entry -> pg -> uninit.aux);
			break;
		
		default:
			vm_alloc_page_with_initializer(page_get_type(src_spt_entry->pg), 
																	src_spt_entry -> vaddr, 
																	src_spt_entry -> is_writable, 
																	copy_init, 
																	src_spt_entry -> pg);
			break;
		}
		vm_claim_page(src_spt_entry -> vaddr);
	}
	lock_release(&src -> lock);
	return true;
}

void page_table_destructor(struct hash_elem *e, void *aux UNUSED){
	debug_msg("Debug: Page TAble destruction\n");
	struct spt_entry *entry = hash_entry(e, struct spt_entry, elem);
	vm_dealloc_page(entry -> pg);
	free(entry);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	lock_acquire(&spt->lock);
	// hash_destroy(spt->page_table, page_table_destructor);
	hash_clear(spt -> page_table, page_table_destructor);
	lock_release(&spt->lock);
}

unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct spt_entry *p = hash_entry (p_, struct spt_entry, elem);
  return hash_bytes (&p->vaddr, sizeof p->vaddr);
}

bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct spt_entry *a = hash_entry (a_, struct spt_entry, elem);
  const struct spt_entry *b = hash_entry (b_, struct spt_entry, elem);

  return a->vaddr < b->vaddr;
}


int debug_msg (const char *format, ...) {
	#ifdef DEBUG
	va_list args;

	va_start (args, format);
  vprintf (format, args);
	va_end (args);
	#else
	return 0;
	#endif
}