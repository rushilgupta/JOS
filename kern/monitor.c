// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/pmap.h>
#include <kern/kdebug.h>
#include <kern/trap.h>
#include <kern/monitor.h>
#include <kern/env.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Prints stack backtrace", mon_backtrace },
	{ "alloc_page", "Allocates a page", mon_alloc_page },
	{ "page_status", "Displays status of a page", mon_page_status },
	{ "free_page", "Free a page", mon_free_page },
	{ "c", "Continue Execution", mon_continue },
	{ "s", "Single Step Execution", mon_single_step },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start %08x (virt)  %08x (phys)\n", _start, _start - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-_start+1023)/1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t ebp	= 0;
	uint32_t eip	= 0;
	uint32_t i;
    
    if (tf == NULL) {
        ebp	= read_ebp();
    } else {
        ebp = tf->tf_regs.reg_ebp;
	    if ((tf->tf_cs & 3) == 3)
            lcr3(curenv->env_cr3);
    }
    cprintf("Trapframe: %x\n", tf);
	cprintf("Stack backtrace:\n");
	while (ebp != 0) {
		eip	= *((uint32_t *)(ebp+0x4));
		//Print stack trace.
		cprintf("\tebp %08x eip %08x args %08x %08x %08x %08x %08x\n", ebp, *((uint32_t *)(ebp+0x4)), *((uint32_t *)(ebp + 0x8)), *((uint32_t *)(ebp + 0xc)), *((uint32_t *)(ebp + 0x10)), *((uint32_t *)(ebp + 0x14)), *((uint32_t *)(ebp + 0x18)));
		//Print File info
		struct Eipdebuginfo info;
		if (debuginfo_eip((uintptr_t)(eip), &info)==0) {
			cprintf("\t\t%s:%d: ",info.eip_file, info.eip_line);
			for (i = 0; i < info.eip_fn_namelen; i++) {
				cprintf("%c", info.eip_fn_name[i]);
			}
			cprintf("+%d\n", eip-info.eip_fn_addr);
		}
		ebp	= *((uint32_t *)ebp);
	}
    if (tf != NULL && ((tf->tf_cs & 3) == 3))
        lcr3(boot_cr3);

	return 0;
}

int
mon_alloc_page(int argc, char **argv, struct Trapframe *tf) {
    struct Page *page;
    if (!page_alloc(&page)) {
        cprintf("\t0x%x\n", page2pa(page));
    }
    return 0;
}
extern struct Page_list page_free_list;	

int
mon_page_status(int argc, char **argv, struct Trapframe *tf) {
    if (argc != 2) {
        cprintf("\t Usage: page_status [Physical Address]\n");
        return -1;
    }
    physaddr_t  addr    = strtol(argv [1], NULL, 16);
    if (addr >=0 && addr < (npage << PGSHIFT)) {
        struct Page *page;
        int found   = 0;
        LIST_FOREACH(page, &page_free_list, pp_link) {
            //cprintf("%x\n", page);
            if (addr == page2pa(page)) {
                found   = 1;
                break;
            }
        }
        if (found == 0)
            cprintf("\tallocated\n");
        else
            cprintf("\tfree\n");
    } else {
        cprintf("\t invalid address\n");
    }
    return 0;
}

int
mon_continue(int argc, char **argv, struct Trapframe *tf) {
    assert(curenv && curenv->env_status == ENV_RUNNABLE);
    curenv->env_tf.tf_eflags    = curenv->env_tf.tf_eflags & (~FL_TF);
    env_run(curenv);
}

int
mon_single_step(int argc, char **argv, struct Trapframe *tf) {
    assert(curenv && curenv->env_status == ENV_RUNNABLE);
    curenv->env_tf.tf_eflags    = curenv->env_tf.tf_eflags | FL_TF;
    env_run(curenv);
}

int
mon_free_page(int argc, char **argv, struct Trapframe *tf) {
    if (argc != 2) {
        cprintf("\t Usage: free_page [Physical Address]\n");
        return -1;
    }
    physaddr_t  addr    = strtol(argv [1], NULL, 16);
    if (addr >=0 && addr < (npage << PGSHIFT)) {
        page_free(pa2page(PTE_ADDR(addr)));
    } else {
        cprintf("\t invalid address\n");
    }
    return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
