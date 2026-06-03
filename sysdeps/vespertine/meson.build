sysdep_sources = files(
    'generic/entry.cpp',
    'generic/syscall.cpp',
    'generic/sysdeps.cpp'
)

sysdep_supported_options = {
  'posix': true,
}

inc = include_directories('include')

libc_sources += sysdep_sources
libc_include_dirs += inc
