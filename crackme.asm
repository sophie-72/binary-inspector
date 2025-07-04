; .interp

; .init
0x1000:	endbr64		; end branch
0x1004:	sub	rsp, 8	; rsp = rsp - 8
0x1008:	mov	rax, qword ptr [rip + 0x2fc1]	; rax = __gmon_start__
0x100f:	test	rax, rax	; test rax, rax
0x1012:	je	0x1016	; if ((rax &  rax) == 0) goto 0x1016
0x1014:	call	rax	; call rax
0x1016:	add	rsp, 8	; rsp = rsp + 8
0x101a:	ret		; return

; .plt
0x1020:	push	qword ptr [rip + 0x2fca]	; stack.push(memory[0x3ff0])
0x1026:	jmp	qword ptr [rip + 0x2fcc]	; goto memory[0x3ff8]
0x102c:	nop	dword ptr [rax]	; no operation
0x1030:	jmp	qword ptr [rip + 0x2fca]	; goto memory[0x4000]
0x1036:	push	0	; stack.push(0)
0x103b:	jmp	0x1020	; goto 0x1020
0x1040:	jmp	qword ptr [rip + 0x2fc2]	; goto memory[0x4008]
0x1046:	push	1	; stack.push(1)
0x104b:	jmp	0x1020	; goto 0x1020
0x1050:	jmp	qword ptr [rip + 0x2fba]	; goto memory[0x4010]
0x1056:	push	2	; stack.push(2)
0x105b:	jmp	0x1020	; goto 0x1020
0x1060:	jmp	qword ptr [rip + 0x2fb2]	; goto memory[0x4018]
0x1066:	push	3	; stack.push(3)
0x106b:	jmp	0x1020	; goto 0x1020
0x1070:	jmp	qword ptr [rip + 0x2faa]	; goto memory[0x4020]
0x1076:	push	4	; stack.push(4)
0x107b:	jmp	0x1020	; goto 0x1020

; .text
0x1080:	endbr64		; end branch
0x1084:	xor	ebp, ebp	; ebp = 0
0x1086:	mov	r9, rdx	; r9 = rdx
0x1089:	pop	rsi	; rsi = stack.pop()
0x108a:	mov	rdx, rsp	; rdx = rsp
0x108d:	and	rsp, 0xfffffffffffffff0	; rsp = rsp & 0xfffffffffffffff0
0x1091:	push	rax	; stack.push(rax)
0x1092:	push	rsp	; stack.push(rsp)
0x1093:	xor	r8d, r8d	; r8d = 0
0x1096:	xor	ecx, ecx	; ecx = 0
0x1098:	lea	rdi, [rip + 0xda]	; rdi = 0x1179
0x109f:	call	qword ptr [rip + 0x2f1b]	; call __libc_start_main
0x10a5:	hlt		; halt
0x10a6:	nop	word ptr cs:[rax + rax]	; no operation
0x10b0:	lea	rdi, [rip + 0x2f81]	; rdi = 0x4038
0x10b7:	lea	rax, [rip + 0x2f7a]	; rax = 0x4038
0x10be:	cmp	rax, rdi	; compare rax, rdi
0x10c1:	je	0x10d8	; if (rax ==  rdi) goto 0x10d8
0x10c3:	mov	rax, qword ptr [rip + 0x2efe]	; rax = _ITM_deregisterTMCloneTable
0x10ca:	test	rax, rax	; test rax, rax
0x10cd:	je	0x10d8	; if ((rax &  rax) == 0) goto 0x10d8
0x10cf:	jmp	rax	; goto rax
0x10d1:	nop	dword ptr [rax]	; no operation
0x10d8:	ret		; return
0x10d9:	nop	dword ptr [rax]	; no operation
0x10e0:	lea	rdi, [rip + 0x2f51]	; rdi = 0x4038
0x10e7:	lea	rsi, [rip + 0x2f4a]	; rsi = 0x4038
0x10ee:	sub	rsi, rdi	; rsi = rsi - rdi
0x10f1:	mov	rax, rsi	; rax = rsi
0x10f4:	shr	rsi, 0x3f	; rsi = (unsigned)rsi >> ?
0x10f8:	sar	rax, 3	; rax = rax >> 3
0x10fc:	add	rsi, rax	; rsi = rsi + rax
0x10ff:	sar	rsi, 1	; rsi = rsi >> 1
0x1102:	je	0x1118	; if (condition) goto 0x1118
0x1104:	mov	rax, qword ptr [rip + 0x2ecd]	; rax = _ITM_registerTMCloneTable
0x110b:	test	rax, rax	; test rax, rax
0x110e:	je	0x1118	; if ((rax &  rax) == 0) goto 0x1118
0x1110:	jmp	rax	; goto rax
0x1112:	nop	word ptr [rax + rax]	; no operation
0x1118:	ret		; return
0x1119:	nop	dword ptr [rax]	; no operation
0x1120:	endbr64		; end branch
0x1124:	cmp	byte ptr [rip + 0x2f1d], 0	; compare memory[0x4048], 0
0x112b:	jne	0x1160	; if (memory[0x404a] !=  0) goto 0x1160
0x112d:	push	rbp	; stack.push(rbp)
0x112e:	cmp	qword ptr [rip + 0x2eaa], 0	; compare __cxa_finalize, 0
0x1136:	mov	rbp, rsp	; rbp = rsp
0x1139:	je	0x1148	; if (condition) goto 0x1148
0x113b:	mov	rdi, qword ptr [rip + 0x2eee]	; rdi = memory[0x4030]
0x1142:	call	qword ptr [rip + 0x2e98]	; call __cxa_finalize
0x1148:	call	0x10b0	; call 0x10b0
0x114d:	mov	byte ptr [rip + 0x2ef4], 1	; memory[0x4048] = 1
0x1154:	pop	rbp	; rbp = stack.pop()
0x1155:	ret		; return
0x1156:	nop	word ptr cs:[rax + rax]	; no operation
0x1160:	ret		; return
0x1161:	nop	word ptr cs:[rax + rax]	; no operation
0x116c:	nop	dword ptr [rax]	; no operation
0x1170:	endbr64		; end branch
0x1174:	jmp	0x10e0	; goto 0x10e0
0x1179:	push	rbp	; stack.push(rbp)
0x117a:	mov	rbp, rsp	; rbp = rsp
0x117d:	sub	rsp, 0x10	; rsp = rsp - 0x10
0x1181:	mov	edi, 9	; edi = 9
0x1186:	call	0x1070	; call 0x1070
0x118b:	mov	qword ptr [rbp - 0x10], rax	; memory[rbp - 0x10] = rax
0x118f:	mov	rax, qword ptr [rbp - 0x10]	; rax = memory[rbp - 0x10]
0x1193:	mov	byte ptr [rax], 0x70	; memory[rax] = p
0x1196:	mov	rax, qword ptr [rbp - 0x10]	; rax = memory[rbp - 0x10]
0x119a:	add	rax, 1	; rax = rax + 1
0x119e:	mov	byte ptr [rax], 0x61	; memory[rax] = a
0x11a1:	mov	rax, qword ptr [rbp - 0x10]	; rax = memory[rbp - 0x10]
0x11a5:	add	rax, 2	; rax = rax + 2
0x11a9:	mov	byte ptr [rax], 0x73	; memory[rax] = s
0x11ac:	mov	rax, qword ptr [rbp - 0x10]	; rax = memory[rbp - 0x10]
0x11b0:	add	rax, 3	; rax = rax + 3
0x11b4:	mov	byte ptr [rax], 0x73	; memory[rax] = s
0x11b7:	mov	rax, qword ptr [rbp - 0x10]	; rax = memory[rbp - 0x10]
0x11bb:	add	rax, 4	; rax = rax + 4
0x11bf:	mov	byte ptr [rax], 0x77	; memory[rax] = w
0x11c2:	mov	rax, qword ptr [rbp - 0x10]	; rax = memory[rbp - 0x10]
0x11c6:	add	rax, 5	; rax = rax + 5
0x11ca:	mov	byte ptr [rax], 0x6f	; memory[rax] = o
0x11cd:	mov	rax, qword ptr [rbp - 0x10]	; rax = memory[rbp - 0x10]
0x11d1:	add	rax, 6	; rax = rax + 6
0x11d5:	mov	byte ptr [rax], 0x72	; memory[rax] = r
0x11d8:	mov	rax, qword ptr [rbp - 0x10]	; rax = memory[rbp - 0x10]
0x11dc:	add	rax, 7	; rax = rax + 7
0x11e0:	mov	byte ptr [rax], 0x64	; memory[rax] = d
0x11e3:	mov	rax, qword ptr [rbp - 0x10]	; rax = memory[rbp - 0x10]
0x11e7:	add	rax, 8	; rax = rax + 8
0x11eb:	mov	byte ptr [rax], 0	; memory[rax] = 0
0x11ee:	mov	edi, 9	; edi = 9
0x11f3:	call	0x1070	; call 0x1070
0x11f8:	mov	qword ptr [rbp - 8], rax	; memory[rbp - 8] = rax
0x11fc:	lea	rax, [rip + 0xe01]	; rax = "Enter the 8 letter password: "
0x1203:	mov	rdi, rax	; rdi = rax
0x1206:	mov	eax, 0	; eax = 0
0x120b:	call	0x1050	; call 0x1050
0x1210:	mov	rdx, qword ptr [rip + 0x2e29]	; rdx = stdin
0x1217:	mov	rax, qword ptr [rbp - 8]	; rax = memory[rbp - 8]
0x121b:	mov	esi, 9	; esi = 9
0x1220:	mov	rdi, rax	; rdi = rax
0x1223:	call	0x1060	; call 0x1060
0x1228:	mov	rcx, qword ptr [rbp - 0x10]	; rcx = memory[rbp - 0x10]
0x122c:	mov	rax, qword ptr [rbp - 8]	; rax = memory[rbp - 8]
0x1230:	mov	edx, 8	; edx = 8
0x1235:	mov	rsi, rcx	; rsi = rcx
0x1238:	mov	rdi, rax	; rdi = rax
0x123b:	call	0x1030	; call 0x1030
0x1240:	test	eax, eax	; test eax, eax
0x1242:	jne	0x1255	; if ((eax &  eax) != 0) goto 0x1255
0x1244:	lea	rax, [rip + 0xdd7]	; rax = "You read my memory"
0x124b:	mov	rdi, rax	; rdi = rax
0x124e:	call	0x1040	; call 0x1040
0x1253:	jmp	0x1264	; goto 0x1264
0x1255:	lea	rax, [rip + 0xdd9]	; rax = "You can't read my memory!"
0x125c:	mov	rdi, rax	; rdi = rax
0x125f:	call	0x1040	; call 0x1040
0x1264:	mov	eax, 0	; eax = 0
0x1269:	leave		; leave
0x126a:	ret		; return

; .fini
0x126c:	endbr64		; end branch
0x1270:	sub	rsp, 8	; rsp = rsp - 8
0x1274:	add	rsp, 8	; rsp = rsp + 8
0x1278:	ret		; return

; .rodata
0x2000:	add	dword ptr [rax], eax	; dword ptr [rax] = dword ptr [rax] + eax
0x2002:	add	al, byte ptr [rax]	; al = al + memory[rax]
0x2004:	outsb	dx, byte ptr [rsi]	; outport(dx, memory[rsi])
0x2006:	je	0x206d	; if (condition) goto 0x206d
0x2008:	jb	0x202a	; if (left < right) goto 0x202a
0x200a:	je	0x2074	; if (condition) goto 0x2074
0x200c:	and	byte ptr gs:[rax], bh	; byte ptr gs:[rax] = byte ptr gs:[rax] & bh
0x200f:	and	byte ptr [rbp + riz*2 + 0x74], ch	; memory[rbp + riz*2 + 0x74] = memory[rbp + riz*2 + 0x74] & ch
0x2013:	je	0x207a	; if (condition) goto 0x207a
0x2015:	jb	0x2037	; if (left < right) goto 0x2037
0x2017:	jo	0x207a	; if (overflow_occurred) goto 0x207a
0x2019:	jae	0x208e	; if (condition) goto 0x208e
0x201b:	ja	0x208c	; if (left > right) goto 0x208c
0x201d:	jb	0x2083	; if (left < right) goto 0x2083
0x201f:	cmp	ah, byte ptr [rax]	; compare ah, memory[rax]
0x2021:	add	byte ptr [rcx + 0x6f], bl	; memory[rcx + 0x6f] = memory[rcx + 0x6f] + bl
0x2024:	jne	0x2046	; if (!condition) goto 0x2046
0x2026:	jb	0x208d	; if (left < right) goto 0x208d

; .eh_frame_hdr
0x2050:	add	dword ptr [rbx], ebx	; dword ptr [rbx] = dword ptr [rbx] + ebx
0x2052:	add	edi, dword ptr [rbx]	; edi = edi + dword ptr [rbx]
0x2054:	and	al, 0	; al = al & 0
0x2056:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x2058:	add	eax, dword ptr [rax]	; eax = eax + dword ptr [rax]
0x205a:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x205c:	shr	bh, 1	; bh = (unsigned)bh >> 1

; .eh_frame
0x2078:	adc	al, 0	; al = al + 0 + carry_flag
0x207a:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x207c:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x207e:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x2080:	add	dword ptr [rdx + 0x52], edi	; dword ptr [rdx + 0x52] = dword ptr [rdx + 0x52] + edi
0x2083:	add	byte ptr [rcx], al	; memory[rcx] = memory[rcx] + al
0x2085:	js	0x2097	; if (result < 0) goto 0x2097
0x2087:	add	dword ptr [rbx], ebx	; dword ptr [rbx] = dword ptr [rbx] + ebx
0x2089:	or	al, 7	; al = al | 7
0x208b:	or	byte ptr [rax + 0x14000001], dl	; memory[rax + 0x14000001] = memory[rax + 0x14000001] | dl
0x2091:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x2093:	add	byte ptr [rax + rax], bl	; memory[rax + rax] = memory[rax + rax] + bl
0x2096:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x2098:	call	0x2700208c	; call 0x2700208c
0x209d:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x209f:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al

; .got
0x3fc0:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fc2:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fc4:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fc6:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fc8:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fca:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fcc:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fce:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fd0:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fd2:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fd4:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fd6:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fd8:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fda:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fdc:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fde:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fe0:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fe2:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fe4:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fe6:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al

; .got.plt
0x3fe8:	loopne	0x4027	; loopne
0x3fea:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fec:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3fee:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3ff0:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3ff2:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3ff4:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3ff6:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3ff8:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3ffa:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3ffc:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x3ffe:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4000:	adc	byte ptr ss:[rax], al	; byte ptr ss:[rax] = byte ptr ss:[rax] + al + carry_flag
0x4003:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4005:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4007:	add	byte ptr [rsi + 0x10], al	; memory[rsi + 0x10] = memory[rsi + 0x10] + al
0x400a:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x400c:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x400e:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4010:	push	rsi	; stack.push(rsi)
0x4011:	adc	byte ptr [rax], al	; memory[rax] = memory[rax] + al + carry_flag
0x4013:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4015:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4017:	add	byte ptr [rsi + 0x10], ah	; memory[rsi + 0x10] = memory[rsi + 0x10] + ah
0x401a:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x401c:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x401e:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4020:	jbe	0x4032	; if (condition) goto 0x4032
0x4022:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4024:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4026:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al

; .data
0x4028:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x402a:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x402c:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x402e:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4030:	xor	byte ptr [rax], al	; memory[rax] = memory[rax] ^ al
0x4033:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4035:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al

; .bss
0x4040:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4042:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4044:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4046:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x4048:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x404a:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x404c:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al
0x404e:	add	byte ptr [rax], al	; memory[rax] = memory[rax] + al

; .comment
0x0:	cmp	spl, byte ptr [r8]	; compare spl, memory[r8]
0x5:	sub	byte ptr [rdi + 0x4e], al	; memory[rdi + 0x4e] = memory[rdi + 0x4e] - al
0x8:	push	rbp	; stack.push(rbp)
0x9:	sub	dword ptr [rax], esp	; dword ptr [rax] = dword ptr [rax] - esp
0xb:	xor	dword ptr [rip + 0x312e312e], esi	; dword ptr [0x312e313f] = dword ptr [0x312e313f] ^ esi
0x11:	and	byte ptr [rdx], dh	; memory[rdx] = memory[rdx] & dh
0x13:	xor	byte ptr [rdx], dh	; memory[rdx] = memory[rdx] ^ dh
0x15:	xor	eax, 0x35323430	; eax = eax ^ 0x35323430

