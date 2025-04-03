	.globl lz4dec_x86_64
	.intel_syntax noprefix
//
// https://github.com/nobodyisnobody/tools/tree/main/Assembly.Decompression.Stubs#2--lz4-compression
// small lz4 decompression stub in x86_64 assembly (60 bytes)
// lz4dec_x86_64(void *dst, void *src, void *srcend);
lz4dec_x86_64:
	push rcx
	push rbx
	push rdi
.l0:
	xor ecx,ecx
	xor eax,eax
	lodsb
	movzx	ebx,al
.cpy:
	shr al,4
	call buildfullcount
	rep movsb
	cmp rsi,rdx
	jae .done2
.copymatches:
	lodsw
	xchg ebx,eax
	and al,15
	call buildfullcount
.matchcopy:
	push rsi
	push rdi
	pop rsi
	sub rsi,rbx
	add ecx,4
	rep movsb
	pop rsi
	jmp .l0

buildfullcount:
	cmp al,15
	xchg ecx,eax
	jne .done1
.buildloop:
	lodsb
	add ecx,eax
	cmp al,255
	je .buildloop
.done1:
	ret
.done2:
	push rdi
	pop rax
	pop rdi
	sub rax,rdi
	pop rbx
	pop rcx
	ret

