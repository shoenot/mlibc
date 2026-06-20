#include <bits/ensure.h>

[[noreturn]] static inline int stub_called(const char *func) {
    (void)func;
    __ensure(!"STUB function was called");
    __builtin_unreachable();
}

#define STUB() do { stub_called(__func__); __builtin_unreachable(); } while(0)

extern "C" {
float _Complex __mulsc3(float a, float b, float c, float d) { STUB(); }
double _Complex __muldc3(double a, double b, double c, double d) { STUB(); }
long double _Complex __mulxc3(long double a, long double b, long double c, long double d) { STUB(); }
}
