mov ecx, [0x600008]
sub ecx, ebx

mov ebx, [0x600004]
xor edx, edx
sub edx, ebx

mov eax, [0x600000]
imul edx

cdq
idiv ecx

mov [0x600008], eax
done: