
#include <string.h>
#include <sys/stat.h>

void strmode(mode_t mode, char *p) {
	switch (mode & S_IFMT) {
		case S_IFDIR:
			p[0] = 'd';
			break;
		case S_IFCHR:
			p[0] = 'c';
			break;
		case S_IFBLK:
			p[0] = 'b';
			break;
		case S_IFREG:
			p[0] = '-';
			break;
		case S_IFLNK:
			p[0] = 'l';
			break;
		case S_IFIFO:
			p[0] = 'p';
			break;
#ifdef S_IFSOCK
		case S_IFSOCK:
			p[0] = 's';
			break;
#endif
		default:
			p[0] = '?';
			break;
	}

	p[1] = (mode & S_IRUSR) ? 'r' : '-';
	p[2] = (mode & S_IWUSR) ? 'w' : '-';
	if (mode & S_ISUID)
		p[3] = (mode & S_IXUSR) ? 's' : 'S';
	else
		p[3] = (mode & S_IXUSR) ? 'x' : '-';

	p[4] = (mode & S_IRGRP) ? 'r' : '-';
	p[5] = (mode & S_IWGRP) ? 'w' : '-';
	if (mode & S_ISGID)
		p[6] = (mode & S_IXGRP) ? 's' : 'S';
	else
		p[6] = (mode & S_IXGRP) ? 'x' : '-';

	p[7] = (mode & S_IROTH) ? 'r' : '-';
	p[8] = (mode & S_IWOTH) ? 'w' : '-';
	if (mode & S_ISVTX)
		p[9] = (mode & S_IXOTH) ? 't' : 'T';
	else
		p[9] = (mode & S_IXOTH) ? 'x' : '-';

	p[10] = ' ';
	p[11] = '\0';
}
