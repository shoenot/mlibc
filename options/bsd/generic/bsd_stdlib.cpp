
#include <bits/ensure.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <stdlib.h>

#include <mlibc/all-sysdeps.hpp>

int getloadavg(double *samples, int nsample) {
	if (nsample < 0) {
		errno = EINVAL;
		return -1;
	}
	if (nsample > 3) {
		nsample = 3;
	}
	double s[3];
	if (int e = mlibc::sysdep_or_enosys<GetLoadavg>(s); e) {
		errno = e;
		return -1;
	}
	for (int i = 0; i < nsample; i++) {
		samples[i] = s[i];
	}
	return nsample;
}

long long strtonum(const char *nptr, long long minval, long long maxval, const char **errstrp) {
	const char *error = nullptr;
	char *end = nullptr;
	int error_number = 0;
	long long value = 0;

	if (minval > maxval) {
		error = "invalid";
		error_number = EINVAL;
	} else {
		errno = 0;
		value = strtoll(nptr, &end, 10);
		if (nptr == end || *end != '\0') {
			error = "invalid";
			error_number = EINVAL;
		} else if ((value == LLONG_MIN && errno == ERANGE) || value < minval) {
			error = "too small";
			error_number = ERANGE;
		} else if ((value == LLONG_MAX && errno == ERANGE) || value > maxval) {
			error = "too large";
			error_number = ERANGE;
		}
	}

	if (errstrp)
		*errstrp = error;
	if (error) {
		errno = error_number;
		return 0;
	}
	return value;
}

char *getbsize(int *headerlenp, long *blocksizep) {
	static char header[32];
	const char *value = getenv("BLOCKSIZE");
	long blocksize = 512;

	if (value && *value) {
		char *end = nullptr;
		errno = 0;
		long parsed = strtol(value, &end, 10);
		unsigned long multiplier = 1;
		if (end && *end) {
			switch (toupper(static_cast<unsigned char>(*end))) {
				case 'E':
					multiplier *= 1024;
					[[fallthrough]];
				case 'P':
					multiplier *= 1024;
					[[fallthrough]];
				case 'T':
					multiplier *= 1024;
					[[fallthrough]];
				case 'G':
					multiplier *= 1024;
					[[fallthrough]];
				case 'M':
					multiplier *= 1024;
					[[fallthrough]];
				case 'K':
					multiplier *= 1024;
					end++;
					break;
				default:
					multiplier = 0;
					break;
			}
			if ((*end == 'B' || *end == 'b') && multiplier)
				end++;
		}
		if (!errno && parsed > 0 && multiplier && end && !*end
		    && static_cast<unsigned long>(parsed) <= LONG_MAX / multiplier)
			blocksize = parsed * static_cast<long>(multiplier);
	}

	long display = blocksize;
	const char *suffix = "";
	if (blocksize % (1024L * 1024 * 1024) == 0) {
		display = blocksize / (1024L * 1024 * 1024);
		suffix = "G";
	} else if (blocksize % (1024L * 1024) == 0) {
		display = blocksize / (1024L * 1024);
		suffix = "M";
	} else if (blocksize % 1024 == 0) {
		display = blocksize / 1024;
		suffix = "K";
	}
	snprintf(header, sizeof(header), "%ld%s-blocks", display, suffix);
	if (headerlenp)
		*headerlenp = strlen(header);
	if (blocksizep)
		*blocksizep = blocksize;
	return header;
}
