#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>


// Choose a user environment to run and run it.
void
sched_yield(void)
{
    int i; //Loop variable for envs.
    int startEnv    = 0;

	// Implement simple round-robin scheduling.
	// Search through 'envs' for a runnable environment,
	// in circular fashion starting after the previously running env,
	// and switch to the first such environment found.
	// It's OK to choose the previously running env if no other env
	// is runnable.
	// But never choose envs[0], the idle environment,
	// unless NOTHING else is runnable.

	// LAB 4: Your code here.
    // Get the curenv Id. We should start searching from the environment
    // after the current one.
    if (curenv != NULL) {
        startEnv    = (int)(&envs[ENVX(curenv->env_id)] - envs);
    }

    for (i=startEnv+1; i!=startEnv;i=((i+1)%(NENV-1))) {
        if (i != 0 && envs[i].env_status == ENV_RUNNABLE) {
            startEnv    = i;
            break;
        }
    }

    // Check if we can run current environement
    if (startEnv==0 && curenv!=NULL && curenv->env_status==ENV_RUNNABLE) {
        startEnv    = ENVX(curenv->env_id);
    }

	// Run the special idle environment when nothing else is runnable.
	if (envs[startEnv].env_status == ENV_RUNNABLE) {
		env_run(&envs[startEnv]);
    }
	else {
		cprintf("Destroyed all environments - nothing more to do!\n");
		while (1)
			monitor(NULL);
	}
}
