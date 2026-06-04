.section .text
.global _start
.type _start, @function

_start:
    xor %ebp, %ebp

    # align stack to 16 byte boundary
    and $~15, %rsp

    call __mlibc_entry

    ud2

.section .note.GNU-stack,"",%progbits
