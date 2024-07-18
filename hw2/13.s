mov eax, [0x600000]
mov ebx, -5
imul ebx

mov ebx, eax

xor eax, eax
mov ecx, [0x600004]
sub eax, ecx

mov ecx, [0x600008]

cdq
idiv ecx

mov ecx, edx
mov eax, ebx

cdq
idiv ecx

mov [0x60000c], eax

done: