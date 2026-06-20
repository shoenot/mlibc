#include <util.h>

#include <errno.h>
#include <stdio.h>

int fmt_scaled(long long number, char *result) {
	if (!result) {
		errno = EINVAL;
		return -1;
	}

	static constexpr char units[] = "BKMGTPE";
	unsigned unit = 0;
	unsigned long long value = number < 0 ? static_cast<unsigned long long>(-(number + 1)) + 1
	                                      : static_cast<unsigned long long>(number);
	unsigned long long scale = 1;

	while (value / scale >= 1024 && unit + 1 < sizeof(units) - 1) {
		scale *= 1024;
		unit++;
	}

	auto whole = value / scale;
	auto tenth = ((value % scale) * 10 + scale / 2) / scale;
	if (tenth == 10) {
		whole++;
		tenth = 0;
	}
	if (whole == 1024 && unit + 1 < sizeof(units) - 1) {
		whole = 1;
		unit++;
	}

	if (number < 0 && tenth)
		snprintf(result, FMT_SCALED_STRSIZE, "-%llu.%llu%c", whole, tenth, units[unit]);
	else if (number < 0)
		snprintf(result, FMT_SCALED_STRSIZE, "-%llu%c", whole, units[unit]);
	else if (tenth)
		snprintf(result, FMT_SCALED_STRSIZE, "%llu.%llu%c", whole, tenth, units[unit]);
	else
		snprintf(result, FMT_SCALED_STRSIZE, "%llu%c", whole, units[unit]);

	return 0;
}
