#include <unistd.h>

/*
 * Vespertine authority is constrained by capabilities supplied at launch.
 * Dynamic pledge-style attenuation is not implemented yet.
 */
extern "C" int pledge(const char *promises, const char *execpromises) {
	(void)promises;
	(void)execpromises;
	return 0;
}
