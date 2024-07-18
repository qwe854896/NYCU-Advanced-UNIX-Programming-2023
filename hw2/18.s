    mov    rdi, 19
    call   r
    jmp    exit

r:
    cmp    rdi, 1
    jle    edge

    push   rdi

    sub    rdi, 1
    call   r
    lea    rax, [rax * 2]
    push   rax

    sub    rdi, 1
    call   r
    lea    rax, [rax + rax * 2]

    pop    rsi
    add    rax, rsi

    pop    rdi
    ret

edge:
    mov rax, rdi
    ret

exit:
done: