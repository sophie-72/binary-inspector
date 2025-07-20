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
0x1098:	lea	rdi, [rip + 0x2a2]	; lea rdi, [0x1341]
0x109f:	call	qword ptr [rip + 0x2f33]	; call __libc_start_main
0x10a5:	hlt		
0x10a6:	nop	word ptr cs:[rax + rax]	
0x10b0:	lea	rdi, [rip + 0x2f61]	; lea rdi, [0x4018]
0x10b7:	lea	rax, [rip + 0x2f5a]	; lea rax, [0x4018]
0x10be:	cmp	rax, rdi	
0x10c1:	je	0x10d8	
0x10c3:	mov	rax, qword ptr [rip + 0x2f16]	; mov rax, _ITM_deregisterTMCloneTable
0x10ca:	test	rax, rax	
0x10cd:	je	0x10d8	
0x10cf:	jmp	rax	
0x10d1:	nop	dword ptr [rax]	
0x10d8:	ret		
0x10d9:	nop	dword ptr [rax]	
0x10e0:	lea	rdi, [rip + 0x2f31]	; lea rdi, [0x4018]
0x10e7:	lea	rsi, [rip + 0x2f2a]	; lea rsi, [0x4018]
0x10ee:	sub	rsi, rdi	
0x10f1:	mov	rax, rsi	
0x10f4:	shr	rsi, 0x3f	
0x10f8:	sar	rax, 3	
0x10fc:	add	rsi, rax	
0x10ff:	sar	rsi, 1	
0x1102:	je	0x1118	
0x1104:	mov	rax, qword ptr [rip + 0x2ee5]	; mov rax, _ITM_registerTMCloneTable
0x110b:	test	rax, rax	
0x110e:	je	0x1118	
0x1110:	jmp	rax	
0x1112:	nop	word ptr [rax + rax]	
0x1118:	ret		
0x1119:	nop	dword ptr [rax]	
0x1120:	endbr64		
0x1124:	cmp	byte ptr [rip + 0x2eed], 0	; cmp memory[0x4018], 0
0x112b:	jne	0x1158	
0x112d:	push	rbp	
0x112e:	cmp	qword ptr [rip + 0x2ec2], 0	; cmp __cxa_finalize, 0
0x1136:	mov	rbp, rsp	
0x1139:	je	0x1147	
0x113b:	mov	rdi, qword ptr [rip + 0x2ec6]	; mov rdi, memory[0x4008]
0x1142:	call	0x1050	
0x1147:	call	0x10b0	; call deregister_tm_clones
0x114c:	mov	byte ptr [rip + 0x2ec5], 1	; mov memory[0x4018], 1
0x1153:	pop	rbp	
0x1154:	ret		
0x1155:	nop	dword ptr [rax]	
0x1158:	ret		
0x1159:	nop	dword ptr [rax]	
0x1160:	endbr64		
0x1164:	jmp	0x10e0	
0x1169:	endbr64		
0x116d:	push	rbp	
0x116e:	mov	rbp, rsp	
0x1171:	mov	dword ptr [rbp - 4], edi	
0x1174:	mov	dword ptr [rbp - 8], esi	
0x1177:	mov	edx, dword ptr [rbp - 4]	
0x117a:	mov	eax, dword ptr [rbp - 8]	
0x117d:	add	eax, edx	
0x117f:	pop	rbp	
0x1180:	ret		
0x1181:	endbr64		
0x1185:	push	rbp	
0x1186:	mov	rbp, rsp	
0x1189:	sub	rsp, 0x10	
0x118d:	mov	dword ptr [rbp - 4], edi	
0x1190:	cmp	dword ptr [rbp - 4], 0	
0x1194:	jle	0x11b6	
0x1196:	mov	eax, dword ptr [rbp - 4]	
0x1199:	mov	esi, eax	
0x119b:	lea	rax, [rip + 0xe75]	; lea rax, ["Positive number: %d"]
0x11a2:	mov	rdi, rax	
0x11a5:	mov	eax, 0	
0x11aa:	call	0x1070	
0x11af:	mov	eax, 1	
0x11b4:	jmp	0x11f0	
0x11b6:	cmp	dword ptr [rbp - 4], 0	
0x11ba:	jns	0x11dc	
0x11bc:	mov	eax, dword ptr [rbp - 4]	
0x11bf:	mov	esi, eax	
0x11c1:	lea	rax, [rip + 0xe64]	; lea rax, ["Negative number: %d"]
0x11c8:	mov	rdi, rax	
0x11cb:	mov	eax, 0	
0x11d0:	call	0x1070	
0x11d5:	mov	eax, 0xffffffff	
0x11da:	jmp	0x11f0	
0x11dc:	lea	rax, [rip + 0xe5e]	; lea rax, ["Zero"]
0x11e3:	mov	rdi, rax	
0x11e6:	call	0x1060	
0x11eb:	mov	eax, 0	
0x11f0:	leave		
0x11f1:	ret		
0x11f2:	endbr64		
0x11f6:	push	rbp	
0x11f7:	mov	rbp, rsp	
0x11fa:	sub	rsp, 0x20	
0x11fe:	mov	dword ptr [rbp - 0x14], edi	
0x1201:	mov	dword ptr [rbp - 4], 0	
0x1208:	jmp	0x1236	
0x120a:	mov	eax, dword ptr [rbp - 4]	
0x120d:	mov	esi, eax	
0x120f:	lea	rax, [rip + 0xe30]	; lea rax, ["Loop iteration %d"]
0x1216:	mov	rdi, rax	
0x1219:	mov	eax, 0	
0x121e:	call	0x1070	
0x1223:	mov	eax, dword ptr [rip + 0x2df3]	; mov eax, dword ptr [0x401c]
0x1229:	add	eax, 1	
0x122c:	mov	dword ptr [rip + 0x2dea], eax	; mov dword ptr [0x401c], eax
0x1232:	add	dword ptr [rbp - 4], 1	
0x1236:	mov	eax, dword ptr [rbp - 4]	
0x1239:	cmp	eax, dword ptr [rbp - 0x14]	
0x123c:	jl	0x120a	
0x123e:	jmp	0x126b	
0x1240:	mov	eax, dword ptr [rip + 0x2dd6]	; mov eax, dword ptr [0x401c]
0x1246:	mov	esi, eax	
0x1248:	lea	rax, [rip + 0xe0a]	; lea rax, ["Global counter: %d"]
0x124f:	mov	rdi, rax	
0x1252:	mov	eax, 0	
0x1257:	call	0x1070	
0x125c:	mov	eax, dword ptr [rip + 0x2dba]	; mov eax, dword ptr [0x401c]
0x1262:	sub	eax, 1	
0x1265:	mov	dword ptr [rip + 0x2db1], eax	; mov dword ptr [0x401c], eax
0x126b:	mov	eax, dword ptr [rip + 0x2dab]	; mov eax, dword ptr [0x401c]
0x1271:	test	eax, eax	
0x1273:	jg	0x1240	
0x1275:	nop		
0x1276:	nop		
0x1277:	leave		
0x1278:	ret		
0x1279:	endbr64		
0x127d:	push	rbp	
0x127e:	mov	rbp, rsp	
0x1281:	sub	rsp, 0x10	
0x1285:	mov	dword ptr [rbp - 4], edi	
0x1288:	cmp	dword ptr [rbp - 4], 3	
0x128c:	je	0x12c4	
0x128e:	cmp	dword ptr [rbp - 4], 3	
0x1292:	jg	0x12d5	
0x1294:	cmp	dword ptr [rbp - 4], 1	
0x1298:	je	0x12a2	
0x129a:	cmp	dword ptr [rbp - 4], 2	
0x129e:	je	0x12b3	
0x12a0:	jmp	0x12d5	
0x12a2:	lea	rax, [rip + 0xdc4]	; lea rax, ["Option 1 selected"]
0x12a9:	mov	rdi, rax	
0x12ac:	call	0x1060	
0x12b1:	jmp	0x12e5	
0x12b3:	lea	rax, [rip + 0xdc5]	; lea rax, ["Option 2 selected"]
0x12ba:	mov	rdi, rax	
0x12bd:	call	0x1060	
0x12c2:	jmp	0x12e5	
0x12c4:	lea	rax, [rip + 0xdc6]	; lea rax, ["Option 3 selected"]
0x12cb:	mov	rdi, rax	
0x12ce:	call	0x1060	
0x12d3:	jmp	0x12e5	
0x12d5:	lea	rax, [rip + 0xdc7]	; lea rax, ["Invalid option"]
0x12dc:	mov	rdi, rax	
0x12df:	call	0x1060	
0x12e4:	nop		
0x12e5:	nop		
0x12e6:	leave		
0x12e7:	ret		
0x12e8:	endbr64		
0x12ec:	push	rbp	
0x12ed:	mov	rbp, rsp	
0x12f0:	mov	dword ptr [rbp - 0x14], edi	
0x12f3:	mov	dword ptr [rbp - 0x18], esi	
0x12f6:	mov	dword ptr [rbp - 8], 0	
0x12fd:	cmp	dword ptr [rbp - 0x14], 0xa	
0x1301:	jle	0x1321	
0x1303:	cmp	dword ptr [rbp - 0x18], 4	
0x1307:	jg	0x1316	
0x1309:	mov	edx, dword ptr [rbp - 0x14]	
0x130c:	mov	eax, dword ptr [rbp - 0x18]	
0x130f:	add	eax, edx	
0x1311:	mov	dword ptr [rbp - 8], eax	
0x1314:	jmp	0x133c	
0x1316:	mov	eax, dword ptr [rbp - 0x14]	
0x1319:	sub	eax, dword ptr [rbp - 0x18]	
0x131c:	mov	dword ptr [rbp - 8], eax	
0x131f:	jmp	0x133c	
0x1321:	mov	dword ptr [rbp - 4], 0	
0x1328:	jmp	0x1334	
0x132a:	mov	eax, dword ptr [rbp - 4]	
0x132d:	add	dword ptr [rbp - 8], eax	
0x1330:	add	dword ptr [rbp - 4], 1	
0x1334:	mov	eax, dword ptr [rbp - 4]	
0x1337:	cmp	eax, dword ptr [rbp - 0x14]	
0x133a:	jl	0x132a	
0x133c:	mov	eax, dword ptr [rbp - 8]	
0x133f:	pop	rbp	
0x1340:	ret		
0x1341:	endbr64		
0x1345:	push	rbp	
0x1346:	mov	rbp, rsp	
0x1349:	sub	rsp, 0x20	
0x134d:	mov	dword ptr [rbp - 0x14], edi	
0x1350:	mov	qword ptr [rbp - 0x20], rsi	; mov memory[rbp - 0x20], rsi
0x1354:	lea	rax, [rip + 0xd57]	; lea rax, ["Binary Inspector Test Program"]
0x135b:	mov	rdi, rax	
0x135e:	call	0x1060	
0x1363:	mov	rax, qword ptr [rip + 0x2ca6]	; mov rax, memory[0x4010]
0x136a:	mov	rsi, rax	
0x136d:	lea	rax, [rip + 0xd5c]	; lea rax, ["Global message: %s"]
0x1374:	mov	rdi, rax	
0x1377:	mov	eax, 0	
0x137c:	call	0x1070	
0x1381:	mov	esi, 3	
0x1386:	mov	edi, 5	
0x138b:	call	0x1169	; call add_numbers
0x1390:	mov	dword ptr [rbp - 8], eax	
0x1393:	mov	eax, dword ptr [rbp - 8]	
0x1396:	mov	esi, eax	
0x1398:	lea	rax, [rip + 0xd45]	; lea rax, ["Sum: %d"]
0x139f:	mov	rdi, rax	
0x13a2:	mov	eax, 0	
0x13a7:	call	0x1070	
0x13ac:	mov	edi, 0xa	
0x13b1:	call	0x1181	; call check_number
0x13b6:	mov	edi, 0xfffffffb	
0x13bb:	call	0x1181	; call check_number
0x13c0:	mov	edi, 0	
0x13c5:	call	0x1181	; call check_number
0x13ca:	mov	edi, 3	
0x13cf:	call	0x11f2	; call print_loop
0x13d4:	mov	edi, 2	
0x13d9:	call	0x1279	; call process_choice
0x13de:	mov	edi, 5	
0x13e3:	call	0x1279	; call process_choice
0x13e8:	mov	esi, 3	
0x13ed:	mov	edi, 0xf	
0x13f2:	call	0x12e8	; call complex_logic
0x13f7:	mov	dword ptr [rbp - 4], eax	
0x13fa:	mov	eax, dword ptr [rbp - 4]	
0x13fd:	mov	esi, eax	
0x13ff:	lea	rax, [rip + 0xce7]	; lea rax, ["Complex result: %d"]
0x1406:	mov	rdi, rax	
0x1409:	mov	eax, 0	
0x140e:	call	0x1070	
0x1413:	cmp	dword ptr [rbp - 0x14], 1	
0x1417:	jle	0x143b	
0x1419:	mov	rax, qword ptr [rbp - 0x20]	; mov rax, memory[rbp - 0x20]
0x141d:	add	rax, 8	
0x1421:	mov	rax, qword ptr [rax]	; mov rax, memory[rax]
0x1424:	mov	rsi, rax	
0x1427:	lea	rax, [rip + 0xcd3]	; lea rax, ["First argument: %s"]
0x142e:	mov	rdi, rax	
0x1431:	mov	eax, 0	
0x1436:	call	0x1070	
0x143b:	mov	eax, 0	
0x1440:	leave		
0x1441:	ret		
