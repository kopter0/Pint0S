/* vm.c: Generic interface for virtual memory objects. */

#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"

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
			struct page new_page;
			bool *initializer;
			switch (type)
			{
			case VM_ANON:
				initializer = &anon_initializer;
				break;
			case VM_FILE:
				initializer = &file_backed_initializer;
				break;
			/*TO_DO: VM_PAGE_CACHE*/
			default:
				PANIC("no match vm_type");
				break;
			}
			
			uninit_new(&new_page, upage ,init, type, aux, initializer);
		/* TODO: Insert the page into the spt. */
		bool insert_succ = spt_insert_page(spt, &new_page);
		return insert_succ;
	}
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct hash_iterator i;

   	hash_first (&i, spt -> page_table);
   	while (hash_next (&i))
	{
		struct spt_entry *f = hash_entry (hash_cur (&i), struct spt_entry, elem);
		if (f -> vaddr == va){
			page = f -> pg;
		}
	}
	
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
	hash_insert(spt -> page_table, &new_entry -> elem);
	succ = true;
	
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = (struct frame *) calloc((size_t) 1, sizeof(frame));
	/* TODO: Fill this function. */
	void* kva = palloc_get_page(PAL_USER);

	if (kva == NULL) {
		PANIC("TODO: EVICT IN vm_get_frame");
	}
	frame -> kva = kva;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
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
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
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
	struct page *page = (struct page*) calloc((size_t) 1, sizeof(struct page));
	/* TODO: Fill this function */
	page -> va = va;
	page -> operations = (struct page_operations *) calloc((size_t) 1, sizeof(struct page_operations));

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
	struct spt_entry *new_entry = (struct spt_entry *) calloc((size_t) 1, sizeof(struct spt_entry));
	new_entry -> pg = page;
	new_entry -> vaddr = page->va;
	new_entry -> paddr = vtop(frame->kva);

	hash_insert(thread_current() -> spt -> page_table, &new_entry -> elem);

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	bool result = hash_init(spt -> page_table, &page_hash, &page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator j;

   	hash_first (&j, src -> page_table);
   	while (hash_next (&j)){
		struct spt_entry *src_spt_entry = hash_entry (hash_cur (&j), struct spt_entry, elem);
	//	vm_alloc_page_with_initializer(src_spt_entry -> vm_type, src_spt_entry -> vaddr, src_spt_entry -> writable, )
		// vm_claim_page() ?
	//	spt_insert_page(dst, );
	}
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct hash_iterator j;

   	hash_first (&j, spt -> page_table);
   	while (hash_next (&j)){
		struct spt_entry *f = hash_entry (hash_cur (&j), struct spt_entry, elem);
		destroy(f -> pg);
	}
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