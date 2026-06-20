#include <grp.h>
#include <pwd.h>
#include <stdio.h>

const char *user_from_uid(uid_t uid, int nouser) {
	if (auto entry = getpwuid(uid); entry)
		return entry->pw_name;
	if (nouser)
		return nullptr;

	static char buffer[32];
	snprintf(buffer, sizeof(buffer), "%u", static_cast<unsigned>(uid));
	return buffer;
}

const char *group_from_gid(gid_t gid, int nogroup) {
	if (auto entry = getgrgid(gid); entry)
		return entry->gr_name;
	if (nogroup)
		return nullptr;

	static char buffer[32];
	snprintf(buffer, sizeof(buffer), "%u", static_cast<unsigned>(gid));
	return buffer;
}
