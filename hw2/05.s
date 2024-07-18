    mov ebx, 0
.L1:
    cmp ebx, 16
    jge .L2

    mov edx, eax
    and edx, 1
    add edx, 48

    mov ecx, 15
    sub ecx, ebx
    
    mov [ecx + 0x600000], DL

    inc ebx
    shr rax, 1
    jmp .L1
.L2:
done: