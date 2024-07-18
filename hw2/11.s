mov eax, [0x600000]
mov ebx, 0
sub ebx, eax
mov eax, [0x600004]
mul ebx
mov ebx, [0x600008]
add eax, ebx
done: