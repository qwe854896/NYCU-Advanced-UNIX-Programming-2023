cmp eax, 0
jge .L1
mov DWORD PTR [0x600000], -1
jmp .L5
.L1:
    mov DWORD PTR [0x600000], 1
.L5:

cmp ebx, 0
jge .L2
mov DWORD PTR [0x600004], -1
jmp .L6
.L2:
    mov DWORD PTR [0x600004], 1
.L6:

cmp ecx, 0
jge .L3
mov DWORD PTR [0x600008], -1
jmp .L7
.L3:
    mov DWORD PTR [0x600008], 1
.L7:

cmp edx, 0
jge .L4
mov DWORD PTR [0x60000c], -1
jmp .L8
.L4:
    mov DWORD PTR [0x60000c], 1
.L8:

done: