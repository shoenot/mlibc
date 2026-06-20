if not bsd_option
	subdir_done()
endif

libc_sources += files(
	'generic/arpa-nameser.cpp',
	'generic/ether.cpp',
	'generic/err.cpp',
	'generic/fts.cpp',
	'generic/getopt.cpp',
	'generic/bsd_stdlib.cpp',
	'generic/bsd_string.cpp',
	'generic/pty.cpp',
	'generic/user_group.cpp',
	'generic/util.cpp',
)

if not no_headers
	install_headers(
		'include/fstab.h',
		'include/fts.h',
		'include/pty.h',
		'include/util.h',
		'include/utmp.h',
	)
	install_headers(
		'include/arpa/nameser.h',
		'include/arpa/nameser_compat.h',
		'include/arpa/telnet.h',
		subdir: 'arpa'
	)
	install_headers(
		'include/sys/queue.h',
		subdir: 'sys'
	)
	install_headers(
		'include/netinet/ether.h',
		subdir: 'netinet'
	)
	install_headers(
		'include/bits/bsd/bsd_grp.h',
		'include/bits/bsd/bsd_pwd.h',
		'include/bits/bsd/bsd_string.h',
		'include/bits/bsd/bsd_stdlib.h',
        'include/bits/bsd/err.h',
		subdir: 'bits/bsd'
	)
endif
