mov eax, [0x600000]
mov ebx, [0x600004]
add eax, ebx
mov ebx, [0x600008]
sub eax, ebx
mov [0x60000c], eax
done: