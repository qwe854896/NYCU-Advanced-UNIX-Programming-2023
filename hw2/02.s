    mov ebx, 0
.L1:
    cmp ebx, 10
    jge .L2

    mov ecx, 0

.L3:
    mov edx, 9
    sub edx, ebx

    cmp ecx, edx
    jge .L4

    mov eax, [0x600000 + ecx * 4]
    mov edx, [0x600000 + ecx * 4 + 4]

    cmp eax, edx
    jle .L5

    mov [0x600000 + ecx * 4], edx
    mov [0x600000 + ecx * 4 + 4], eax

.L5:
    inc ecx
    jmp .L3

.L4:
    inc ebx
    jmp .L1

.L2:

done: