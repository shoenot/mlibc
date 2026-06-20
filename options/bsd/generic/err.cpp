#include <bits/bsd/err.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vwarnc(int code, const char *fmt, va_list params) {
	fprintf(stderr, "%s: ", program_invocation_short_name);
	if(fmt) {
		vfprintf(stderr, fmt, params);
		fputs(": ", stderr);
	}
	fprintf(stderr, "%s\n", strerror(code));
}

void warnc(int code, const char *fmt, ...) {
	va_list params;
	va_start(params, fmt);
	vwarnc(code, fmt, params);
	va_end(params);
}

void verrc(int status, int code,
		const char *fmt, va_list params) {
	vwarnc(code, fmt, params);
	exit(status);
}

void errc(int status, int code, const char *fmt, ...) {
	va_list params;
	va_start(params, fmt);
	verrc(status, code, fmt, params);
}
