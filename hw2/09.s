    mov ebx, 0
.L1:
    cmp ebx, 16
    jge .L2

    mov ecx, [ebx + 0x600000]
    
    test ecx, 64
    jz .L2

    or ecx, 32

    mov [ebx + 0x600010], CL

    inc ebx
    jmp .L1
.L2:
done: