
#include "fs.h"

// Return the virtual address of this disk block.
void*
diskaddr(uint32_t blockno)
{
	if (blockno == 0 || (super && blockno >= super->s_nblocks))
		panic("bad block number %08x in diskaddr", blockno);
	return (char*) (DISKMAP + blockno * BLKSIZE);
}

// Is this virtual address mapped?
bool
va_is_mapped(void *va)
{
	return (vpd[PDX(va)] & PTE_P) && (vpt[VPN(va)] & PTE_P);
}

// Is this virtual address dirty?
bool
va_is_dirty(void *va)
{
	return (vpt[VPN(va)] & PTE_D) != 0;
}

// Fault any disk block that is read or written in to memory by
// loading it from disk.
// Hint: Use ide_read and BLKSECTS.
static void
bc_pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t blockno = ((uint32_t)addr - DISKMAP) / BLKSIZE;
    void *alignedAddr = (void *)(DISKMAP + blockno*BLKSIZE);
	int r;

	// Check that the fault was within the block cache region
	if (addr < (void*)DISKMAP || addr >= (void*)(DISKMAP + DISKSIZE))
		panic("page fault in FS: eip %08x, va %08x, err %04x",
		      utf->utf_eip, addr, utf->utf_err);

	// Allocate a page in the disk map region and read the
	// contents of the block from the disk into that page.
	//
	// LAB 5: Your code here
    if ((r=sys_page_alloc(env->env_id, alignedAddr, PTE_P|PTE_U|PTE_W))<0)
        panic("bc_pgfault: page_alloc error: %e", r);
    
    if (bitmap) {
	    bitmap[blockno/32]  &= ~((1 << (blockno % 32)));
        //cprintf("blockno:%d 0x%x\n", blockno, bitmap[blockno/32]);
    }

    if ((r=ide_read(blockno*BLKSECTS, alignedAddr, BLKSECTS))<0) {
        panic("bc_pgfault: ide_read error: %e", r);
    }

	// Sanity check the block number. (exercise for the reader:
	// why do we do this *after* reading the block in?)
	if (super && blockno >= super->s_nblocks)
		panic("reading non-existent block %08x\n", blockno);

	// Check that the block we read was allocated.
	if (bitmap && block_is_free(blockno))
		panic("reading free block %08x\n", blockno);
}

// Flush the contents of the block containing VA out to disk if
// necessary, then clear the PTE_D bit using sys_page_map.
// If the block is not in the block cache or is not dirty, does
// nothing.
// Hint: Use va_is_mapped, va_is_dirty, and ide_write.
// Hint: Use the PTE_USER constant when calling sys_page_map.
// Hint: Don't forget to round addr down.
void
flush_block(void *addr)
{
	uint32_t blockno = ((uint32_t)addr - DISKMAP) / BLKSIZE;
    void *alignedAddr = (void *)(((int)addr>>PGSHIFT)<<PGSHIFT);
    int r;

	if (addr < (void*)DISKMAP || addr >= (void*)(DISKMAP + DISKSIZE))
		panic("flush_block of bad va %08x", addr);

    if (va_is_dirty(addr)) {
        if ((r=ide_write(blockno*BLKSECTS, alignedAddr, BLKSECTS))<0) {
            panic("flush_block ide_write error: %e", r);
        }
        if ((r=sys_page_map(env->env_id, alignedAddr, env->env_id, alignedAddr, PTE_P|PTE_U|PTE_W))<0) {
            panic("flush_block sys_page_map error: %e", r);
        }
    }
}

// Test that the block cache works, by smashing the superblock and
// reading it back.
static void
check_bc(void)
{
	struct Super backup;

	// back up super block
	memmove(&backup, diskaddr(1), sizeof backup);

	// smash it 
	strcpy(diskaddr(1), "OOPS!\n");
	flush_block(diskaddr(1));
	assert(va_is_mapped(diskaddr(1)));
	assert(!va_is_dirty(diskaddr(1)));

	// clear it out
	sys_page_unmap(0, diskaddr(1));
	assert(!va_is_mapped(diskaddr(1)));

	// read it back in
	assert(strcmp(diskaddr(1), "OOPS!\n") == 0);

	// fix it
	memmove(diskaddr(1), &backup, sizeof backup);
	flush_block(diskaddr(1));

	cprintf("block cache is good\n");
}

void
bc_init(void)
{
	set_pgfault_handler(bc_pgfault);
	check_bc();
}

