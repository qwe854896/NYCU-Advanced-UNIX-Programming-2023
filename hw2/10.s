mov rax, [0x600000]
mov rbx, [0x600004]
add rax, rbx
mov rdx, [0x600008]
mul rdx
mov [0x60000c], eax
done: