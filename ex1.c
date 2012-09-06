//
// Simple inline assembly example
// 
// For JOS lab 1 exercise 1
//

#include <stdio.h>

int
main(int argc, char **argv)
{
	int x = 1;
	printf("Hello x = %d\n", x);

	asm(
		"incl %1\n\t"
		"movl %1,%0\n\t"
		: "=r" (x)
		: "r" (x)
		);

	printf("Hello x = %d after increment\n", x);

	if(x == 2){
	printf("OK\n");
	}
	else{
	printf("ERROR\n");
	}

	return 0;
}
