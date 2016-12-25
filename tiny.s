  .globl _start
  .text
  _start:
                xorl    %eax, %eax
                incl    %eax
                int     $0x80
