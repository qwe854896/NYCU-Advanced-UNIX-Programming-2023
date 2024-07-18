mov eax, [0x600000]
lea ebx, [0]
sub ebx, eax
mov eax, [0x600004]
mov ecx, [0x600008]
sub eax, ecx
add ebx, eax
mov [0x60000c], ebx
done: