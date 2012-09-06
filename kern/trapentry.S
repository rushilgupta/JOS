/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* The TRAPHANDLER macro defines a globally-visible function for handling
 * a trap.  It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 */ 
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text
/**
 * Lab 3: Your code here for generating entry points for the different traps.
 **/
    TRAPHANDLER_NOEC(divideHandler, T_DIVIDE)
    TRAPHANDLER_NOEC(debugHandler, T_DEBUG)
    TRAPHANDLER_NOEC(nmiHandler, T_NMI)
    TRAPHANDLER_NOEC(brkptHandler, T_BRKPT)
    TRAPHANDLER_NOEC(oflowHandler, T_OFLOW)
    TRAPHANDLER_NOEC(boundHandler, T_BOUND)
    TRAPHANDLER_NOEC(illopHandler, T_ILLOP)
    TRAPHANDLER_NOEC(deviceHandler, T_DEVICE)
    TRAPHANDLER(dblFaultHandler, T_DBLFLT)

    TRAPHANDLER(tssHandler, T_TSS)
    TRAPHANDLER(segnpHandler, T_SEGNP)
    TRAPHANDLER(stackHandler, T_STACK)
    TRAPHANDLER(gpfltHandler, T_GPFLT)
    TRAPHANDLER(pgfltHandler, T_PGFLT)

    TRAPHANDLER_NOEC(fperrHandler, T_FPERR)
    TRAPHANDLER(alignHandler, T_ALIGN)
    TRAPHANDLER_NOEC(mchkHandler, T_MCHK)
    TRAPHANDLER_NOEC(simderrHandler, T_SIMDERR)

/**
 * Device IRQs
 **/
    TRAPHANDLER_NOEC(irq32Handler, 32)
    TRAPHANDLER_NOEC(irq33Handler, 33)
    TRAPHANDLER_NOEC(irq34Handler, 34)
    TRAPHANDLER_NOEC(irq35Handler, 35)
    TRAPHANDLER_NOEC(irq36Handler, 36)
    TRAPHANDLER_NOEC(irq37Handler, 37)
    TRAPHANDLER_NOEC(irq38Handler, 38)
    TRAPHANDLER_NOEC(irq39Handler, 39)
    TRAPHANDLER_NOEC(irq40Handler, 40)
    TRAPHANDLER_NOEC(irq41Handler, 41)
    TRAPHANDLER_NOEC(irq42Handler, 42)
    TRAPHANDLER_NOEC(irq43Handler, 43)
    TRAPHANDLER_NOEC(irq44Handler, 44)
    TRAPHANDLER_NOEC(irq45Handler, 45)
    TRAPHANDLER_NOEC(irq46Handler, 46)
    TRAPHANDLER_NOEC(irq47Handler, 47)
    TRAPHANDLER_NOEC(syscallHandler, T_SYSCALL)

/*
 * Lab 3: Your code here for _alltraps
 */
    _alltraps:
    pushl %ds
    pushl %es
    pushal
    cli
    movl $GD_KD, %eax
    movw %ax, %ds
    movw %ax, %es
    push %esp
    call trap
    pop %esp
    popal
    popl %es
    popl %ds
    sub $0x8, %esp
    iret
