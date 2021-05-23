/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/malloc.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static uint32_t total_idxs;
static struct lock swap_lock;
static struct hash *index_table;
struct idx_t_entry {
	uint32_t idx;
	struct hash_elem elem;
};
uint32_t last_idx;

unsigned idx_hash (const struct hash_elem *p, void *aux UNUSED) {
	const struct idx_t_entry *ite = hash_entry(p, struct idx_t_entry, elem);
	return hash_bytes(&ite -> idx, sizeof(uint32_t));
};

bool idx_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
	const struct idx_t_entry *itea = hash_entry(a, struct idx_t_entry, elem);
	const struct idx_t_entry *iteb = hash_entry(b, struct idx_t_entry, elem);
	return itea->idx < iteb -> idx; 
};

static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	total_idxs = disk_size(swap_disk) / 8;
	lock_init(&swap_lock);
	index_table = malloc(sizeof(struct hash));
	hash_init(index_table, idx_hash, idx_less, NULL);
	last_idx = 0;
	debug_msg("SWAP DISK %d\n", disk_size(swap_disk));
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page -> swapped_out = false;
	anon_page -> swap_idx = 0;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	ASSERT(anon_page->swapped_out);

	// printf("Swapping in 0x%x\n", page->va);

	uint32_t idx = anon_page->swap_idx;

	lock_acquire(&swap_lock);
	for (uint32_t i = 0; i < 8; i++) {
		disk_read(swap_disk, idx * 8 + i, kva + 512 * i);
	}
	struct idx_t_entry ite;
	ite.idx = idx;
	struct hash_elem *e = hash_delete(index_table, &ite.elem);
	struct idx_t_entry *fite = hash_entry(e, struct idx_t_entry, elem);
	ASSERT(fite);
	free(fite);

	anon_page->swap_idx = 0;
	anon_page->swapped_out = false;	

	lock_release(&swap_lock);

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	// printf("swap out 0x%x\n", page-> va);
  uint32_t available_idx = (last_idx + 1) % total_idxs;
	lock_acquire(&swap_lock);
	struct idx_t_entry *ite = malloc(sizeof(struct idx_t_entry));
	do  {
		ite->idx = available_idx;
		if (!hash_find(index_table, &ite->elem)){
			hash_insert(index_table, &ite->elem);
			break;
		}
		available_idx = (available_idx + 1) % total_idxs;
	} while (available_idx != last_idx);

	if (available_idx == last_idx){
		PANIC("SWAP OUT: NO MORE SLOTS");
	}

	for (uint32_t i = 0; i < 8; i++) 
		disk_write(swap_disk, available_idx * 8 + i, page -> frame -> kva + 512 * i);

	anon_page->swap_idx = available_idx;
	anon_page->swapped_out = true;	

	last_idx = available_idx;

	page -> frame = NULL;
	lock_release(&swap_lock);
	// printf("SWAPPED out\n");
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	if (anon_page -> swapped_out){
		lock_acquire(&swap_lock);
		struct idx_t_entry ite;
		ite.idx = page->anon.swap_idx;
		struct hash_elem *e;
		e = hash_delete(index_table, &ite.elem);
		lock_release(&swap_lock);
	}
	// else{
	// 	free (page -> frame);
	// }
}
