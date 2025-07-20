0x1080:	endbr64		
0x1084:	xor	ebp, ebp	
0x1086:	mov	r9, rdx	
0x1089:	pop	rsi	
0x108a:	mov	rdx, rsp	
0x108d:	and	rsp, 0xfffffffffffffff0	
0x1091:	push	rax	
0x1092:	push	rsp	
0x1093:	xor	r8d, r8d	
0x1096:	xor	ecx, ecx	
0x1098:	lea	rdi, [rip + 0xda]	; lea rdi, [0x1179]
0x109f:	call	qword ptr [rip + 0x2f1b]	; call __libc_start_main
0x10a5:	hlt		
0x10a6:	nop	word ptr cs:[rax + rax]	
0x10b0:	lea	rdi, [rip + 0x2f81]	; lea rdi, [0x4038]
0x10b7:	lea	rax, [rip + 0x2f7a]	; lea rax, [0x4038]
0x10be:	cmp	rax, rdi	
0x10c1:	je	0x10d8	
0x10c3:	mov	rax, qword ptr [rip + 0x2efe]	; mov rax, _ITM_deregisterTMCloneTable
0x10ca:	test	rax, rax	
0x10cd:	je	0x10d8	
0x10cf:	jmp	rax	
0x10d1:	nop	dword ptr [rax]	
0x10d8:	ret		
0x10d9:	nop	dword ptr [rax]	
0x10e0:	lea	rdi, [rip + 0x2f51]	; lea rdi, [0x4038]
0x10e7:	lea	rsi, [rip + 0x2f4a]	; lea rsi, [0x4038]
0x10ee:	sub	rsi, rdi	
0x10f1:	mov	rax, rsi	
0x10f4:	shr	rsi, 0x3f	
0x10f8:	sar	rax, 3	
0x10fc:	add	rsi, rax	
0x10ff:	sar	rsi, 1	
0x1102:	je	0x1118	
0x1104:	mov	rax, qword ptr [rip + 0x2ecd]	; mov rax, _ITM_registerTMCloneTable
0x110b:	test	rax, rax	
0x110e:	je	0x1118	
0x1110:	jmp	rax	
0x1112:	nop	word ptr [rax + rax]	
0x1118:	ret		
0x1119:	nop	dword ptr [rax]	
0x1120:	endbr64		
0x1124:	cmp	byte ptr [rip + 0x2f1d], 0	; cmp memory[0x4048], 0
0x112b:	jne	0x1160	
0x112d:	push	rbp	
0x112e:	cmp	qword ptr [rip + 0x2eaa], 0	; cmp __cxa_finalize, 0
0x1136:	mov	rbp, rsp	
0x1139:	je	0x1148	
0x113b:	mov	rdi, qword ptr [rip + 0x2eee]	; mov rdi, memory[0x4030]
0x1142:	call	qword ptr [rip + 0x2e98]	; call __cxa_finalize
0x1148:	call	0x10b0	
0x114d:	mov	byte ptr [rip + 0x2ef4], 1	; mov memory[0x4048], 1
0x1154:	pop	rbp	
0x1155:	ret		
0x1156:	nop	word ptr cs:[rax + rax]	
0x1160:	ret		
0x1161:	nop	word ptr cs:[rax + rax]	
0x116c:	nop	dword ptr [rax]	
0x1170:	endbr64		
0x1174:	jmp	0x10e0	
0x1179:	push	rbp	
0x117a:	mov	rbp, rsp	
0x117d:	sub	rsp, 0x10	
0x1181:	mov	edi, 9	
0x1186:	call	0x1070	
0x118b:	mov	qword ptr [rbp - 0x10], rax	; mov memory[rbp - 0x10], rax
0x118f:	mov	rax, qword ptr [rbp - 0x10]	; mov rax, memory[rbp - 0x10]
0x1193:	mov	byte ptr [rax], 0x70	; mov memory[rax], 0x70
0x1196:	mov	rax, qword ptr [rbp - 0x10]	; mov rax, memory[rbp - 0x10]
0x119a:	add	rax, 1	
0x119e:	mov	byte ptr [rax], 0x61	; mov memory[rax], 0x61
0x11a1:	mov	rax, qword ptr [rbp - 0x10]	; mov rax, memory[rbp - 0x10]
0x11a5:	add	rax, 2	
0x11a9:	mov	byte ptr [rax], 0x73	; mov memory[rax], 0x73
0x11ac:	mov	rax, qword ptr [rbp - 0x10]	; mov rax, memory[rbp - 0x10]
0x11b0:	add	rax, 3	
0x11b4:	mov	byte ptr [rax], 0x73	; mov memory[rax], 0x73
0x11b7:	mov	rax, qword ptr [rbp - 0x10]	; mov rax, memory[rbp - 0x10]
0x11bb:	add	rax, 4	
0x11bf:	mov	byte ptr [rax], 0x77	; mov memory[rax], 0x77
0x11c2:	mov	rax, qword ptr [rbp - 0x10]	; mov rax, memory[rbp - 0x10]
0x11c6:	add	rax, 5	
0x11ca:	mov	byte ptr [rax], 0x6f	; mov memory[rax], 0x6f
0x11cd:	mov	rax, qword ptr [rbp - 0x10]	; mov rax, memory[rbp - 0x10]
0x11d1:	add	rax, 6	
0x11d5:	mov	byte ptr [rax], 0x72	; mov memory[rax], 0x72
0x11d8:	mov	rax, qword ptr [rbp - 0x10]	; mov rax, memory[rbp - 0x10]
0x11dc:	add	rax, 7	
0x11e0:	mov	byte ptr [rax], 0x64	; mov memory[rax], 0x64
0x11e3:	mov	rax, qword ptr [rbp - 0x10]	; mov rax, memory[rbp - 0x10]
0x11e7:	add	rax, 8	
0x11eb:	mov	byte ptr [rax], 0	; mov memory[rax], 0
0x11ee:	mov	edi, 9	
0x11f3:	call	0x1070	
0x11f8:	mov	qword ptr [rbp - 8], rax	; mov memory[rbp - 8], rax
0x11fc:	lea	rax, [rip + 0xe01]	; lea rax, ["Enter the 8 letter password: "]
0x1203:	mov	rdi, rax	
0x1206:	mov	eax, 0	
0x120b:	call	0x1050	
0x1210:	mov	rdx, qword ptr [rip + 0x2e29]	; mov rdx, stdin
0x1217:	mov	rax, qword ptr [rbp - 8]	; mov rax, memory[rbp - 8]
0x121b:	mov	esi, 9	
0x1220:	mov	rdi, rax	
0x1223:	call	0x1060	
0x1228:	mov	rcx, qword ptr [rbp - 0x10]	; mov rcx, memory[rbp - 0x10]
0x122c:	mov	rax, qword ptr [rbp - 8]	; mov rax, memory[rbp - 8]
0x1230:	mov	edx, 8	
0x1235:	mov	rsi, rcx	
0x1238:	mov	rdi, rax	
0x123b:	call	0x1030	
0x1240:	test	eax, eax	
0x1242:	jne	0x1255	
0x1244:	lea	rax, [rip + 0xdd7]	; lea rax, ["You read my memory"]
0x124b:	mov	rdi, rax	
0x124e:	call	0x1040	
0x1253:	jmp	0x1264	
0x1255:	lea	rax, [rip + 0xdd9]	; lea rax, ["You can't read my memory!"]
0x125c:	mov	rdi, rax	
0x125f:	call	0x1040	
0x1264:	mov	eax, 0	
0x1269:	leave		
0x126a:	ret		
