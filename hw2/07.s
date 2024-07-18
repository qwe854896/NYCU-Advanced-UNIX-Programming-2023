mov CX, AX
shr CX, 5
and CL, 127
mov [0x600000], CL
done: