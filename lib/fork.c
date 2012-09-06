// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

extern volatile struct Env *env;
extern void _pgfault_upcall(void);
void (*_pgfault_handler)(struct UTrapframe *utf);

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800
//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;
    int perm    = vpt[VPN(addr)]&PTE_USER;
    void *align = (void *)((int)addr&(~0xFFF));
    envid_t envid   = sys_getenvid();
	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at vpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
    if(!(err&FEC_PR)) {
        r   = sys_page_alloc(envid, (void *)align, err&PTE_USER&(~PTE_COW));
        if (!r) {
            panic("Alloc Error: %x Addr: %x\n", r, align);
        }
        return;
    } else if (!(err&FEC_WR) && !(perm&PTE_COW)) {
        panic("Invalid Faulting Access. Access: %x Err: %x\n", perm, err);
    } 

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.
	// LAB 4: Your code here.
    perm    &= (~PTE_COW);
    perm    |= PTE_W;
    if (!(r=sys_page_alloc(envid, (void *)PFTEMP, perm))) {
        memmove((void *)PFTEMP, align, PGSIZE);
        if((r=sys_page_map(envid, (void *)PFTEMP, envid, align, perm))) {
            panic("sys_page_map. Error: 0x%x\n", r);
        }
        if ((r=sys_page_unmap(envid, (void *)PFTEMP))) {
            panic("sys_page_unmap. Error: 0x%x\n", r);
        }
    } else {
        panic("sys_page_alloc. Error: %d\n", r);
    }
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
// 
static int
duppage(envid_t envid, unsigned pn)
{
	int r   = 0;
    int perm    = vpt[VPN(pn)]&PTE_USER;
    int i;
    envid_t env_id  = sys_getenvid();

	// LAB 4: Your code here.
    if (perm&PTE_W) {
        perm    &= (~PTE_W);
        perm    |= PTE_COW;
    }

    if ((perm&PTE_P) && !(r=sys_page_map(env_id, (void *)pn, envid, (void *)pn, perm))) {
        // Map permissions back to parent on COW.
        if ((perm&PTE_COW) && !(r=sys_page_map(envid, (void *)pn, env_id, (void *)pn, perm))) {
        } if (r!=0){
            cprintf("[0x%x] PARENT: sys_page_map. Error: %d\n", env_id, r);
        }
    } else if (r!=0) {
        cprintf("[0x%x] CHILD: sys_page_map. Address 0x%x. Error: %d\n", env_id, pn, r);
    }
    return r;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use vpd, vpt, and duppage.
//   Remember to fix "env" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
    int r   = 0;
    int i;
    envid_t childId = 0;
	// LAB 4: Your code here.
    // Setup parent process pgfault handler.
    set_pgfault_handler(pgfault);

    if ((childId=sys_exofork())<0) {
        panic("Parent: sys_exofork. Error: 0x%x\n", childId);
    } else if (childId>0) {
        // Setup child process' pgfault handler.
        if ((r=sys_env_set_pgfault_upcall(childId, _pgfault_upcall))) {
            panic("Child: sys_env_set_pgfault_upcall. Error: %d\n", r);
        }
        
        // Setup child's Image.
        // Allocate page for child's user exception stack.
        if ((r=sys_page_alloc(childId, (void *)(UXSTACKTOP-PGSIZE), PTE_U|PTE_P|PTE_W))<0) {
            panic("Parent: sys_page_alloc. Error: 0x%x\n", r);           
        }

        // Copy Parent's address space to child.
        for (i=UTEXT;i<USTACKTOP;i+=PGSIZE) {
            if (vpd[VPD(i)]&PTE_P) {
                duppage(childId, i);
            }
        }

        // Set child as runnable.
        if ((r = sys_env_set_status(childId, ENV_RUNNABLE)) < 0) {
            panic("Parent: sys_env_set_status: %e\n", r);
        }
    } else if (childId==0) {
        envid_t envid;
        _pgfault_handler = pgfault;
        envid   = sys_getenvid();
        env = &envs [ENVX(envid)];
    }
    return childId;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
