.section .text
.global _start
.type _start, @function

_start:
    xor %ebp, %ebp
    mov %rsp, %rdi       # Pass the stack pointer to __mlibc_entry
    and $~15, %rsp
    call __mlibc_entry
    ud2

.section .note.GNU-stack,"",%progbits
