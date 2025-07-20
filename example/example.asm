0x10a0:	endbr64		
0x10a4:	xor	ebp, ebp	
0x10a6:	mov	r9, rdx	
0x10a9:	pop	rsi	
0x10aa:	mov	rdx, rsp	
0x10ad:	and	rsp, 0xfffffffffffffff0	
0x10b1:	push	rax	
0x10b2:	push	rsp	
0x10b3:	xor	r8d, r8d	
0x10b6:	xor	ecx, ecx	
0x10b8:	lea	rdi, [rip + 0x44c]	; lea rdi, [0x150b]
0x10bf:	call	qword ptr [rip + 0x2f13]	; call __libc_start_main
0x10c5:	hlt		
0x10c6:	nop	word ptr cs:[rax + rax]	
0x10d0:	lea	rdi, [rip + 0x2f41]	; lea rdi, [0x4018]
0x10d7:	lea	rax, [rip + 0x2f3a]	; lea rax, [0x4018]
0x10de:	cmp	rax, rdi	
0x10e1:	je	0x10f8	
0x10e3:	mov	rax, qword ptr [rip + 0x2ef6]	; mov rax, _ITM_deregisterTMCloneTable
0x10ea:	test	rax, rax	
0x10ed:	je	0x10f8	
0x10ef:	jmp	rax	
0x10f1:	nop	dword ptr [rax]	
0x10f8:	ret		
0x10f9:	nop	dword ptr [rax]	
0x1100:	lea	rdi, [rip + 0x2f11]	; lea rdi, [0x4018]
0x1107:	lea	rsi, [rip + 0x2f0a]	; lea rsi, [0x4018]
0x110e:	sub	rsi, rdi	
0x1111:	mov	rax, rsi	
0x1114:	shr	rsi, 0x3f	
0x1118:	sar	rax, 3	
0x111c:	add	rsi, rax	
0x111f:	sar	rsi, 1	
0x1122:	je	0x1138	
0x1124:	mov	rax, qword ptr [rip + 0x2ec5]	; mov rax, _ITM_registerTMCloneTable
0x112b:	test	rax, rax	
0x112e:	je	0x1138	
0x1130:	jmp	rax	
0x1132:	nop	word ptr [rax + rax]	
0x1138:	ret		
0x1139:	nop	dword ptr [rax]	
0x1140:	endbr64		
0x1144:	cmp	byte ptr [rip + 0x2ecd], 0	; cmp memory[0x4018], 0
0x114b:	jne	0x1178	
0x114d:	push	rbp	
0x114e:	cmp	qword ptr [rip + 0x2ea2], 0	; cmp __cxa_finalize, 0
0x1156:	mov	rbp, rsp	
0x1159:	je	0x1167	
0x115b:	mov	rdi, qword ptr [rip + 0x2ea6]	; mov rdi, memory[0x4008]
0x1162:	call	0x1060	
0x1167:	call	0x10d0	; call deregister_tm_clones
0x116c:	mov	byte ptr [rip + 0x2ea5], 1	; mov memory[0x4018], 1
0x1173:	pop	rbp	
0x1174:	ret		
0x1175:	nop	dword ptr [rax]	
0x1178:	ret		
0x1179:	nop	dword ptr [rax]	
0x1180:	endbr64		
0x1184:	jmp	0x1100	
0x1189:	endbr64		
0x118d:	push	rbp	
0x118e:	mov	rbp, rsp	
0x1191:	mov	dword ptr [rbp - 4], edi	
0x1194:	mov	dword ptr [rbp - 8], esi	
0x1197:	mov	edx, dword ptr [rbp - 4]	
0x119a:	mov	eax, dword ptr [rbp - 8]	
0x119d:	add	eax, edx	
0x119f:	pop	rbp	
0x11a0:	ret		
0x11a1:	endbr64		
0x11a5:	push	rbp	
0x11a6:	mov	rbp, rsp	
0x11a9:	sub	rsp, 0x10	
0x11ad:	mov	dword ptr [rbp - 4], edi	
0x11b0:	cmp	dword ptr [rbp - 4], 0	
0x11b4:	jle	0x11d6	
0x11b6:	mov	eax, dword ptr [rbp - 4]	
0x11b9:	mov	esi, eax	
0x11bb:	lea	rax, [rip + 0xe59]	; lea rax, ["Positive number: %d"]
0x11c2:	mov	rdi, rax	
0x11c5:	mov	eax, 0	
0x11ca:	call	0x1090	
0x11cf:	mov	eax, 1	
0x11d4:	jmp	0x1210	
0x11d6:	cmp	dword ptr [rbp - 4], 0	
0x11da:	jns	0x11fc	
0x11dc:	mov	eax, dword ptr [rbp - 4]	
0x11df:	mov	esi, eax	
0x11e1:	lea	rax, [rip + 0xe48]	; lea rax, ["Negative number: %d"]
0x11e8:	mov	rdi, rax	
0x11eb:	mov	eax, 0	
0x11f0:	call	0x1090	
0x11f5:	mov	eax, 0xffffffff	
0x11fa:	jmp	0x1210	
0x11fc:	lea	rax, [rip + 0xe42]	; lea rax, ["Zero"]
0x1203:	mov	rdi, rax	
0x1206:	call	0x1070	
0x120b:	mov	eax, 0	
0x1210:	leave		
0x1211:	ret		
0x1212:	endbr64		
0x1216:	push	rbp	
0x1217:	mov	rbp, rsp	
0x121a:	sub	rsp, 0x20	
0x121e:	mov	dword ptr [rbp - 0x14], edi	
0x1221:	mov	dword ptr [rbp - 4], 0	
0x1228:	jmp	0x1256	
0x122a:	mov	eax, dword ptr [rbp - 4]	
0x122d:	mov	esi, eax	
0x122f:	lea	rax, [rip + 0xe14]	; lea rax, ["Loop iteration %d"]
0x1236:	mov	rdi, rax	
0x1239:	mov	eax, 0	
0x123e:	call	0x1090	
0x1243:	mov	eax, dword ptr [rip + 0x2dd3]	; mov eax, dword ptr [0x401c]
0x1249:	add	eax, 1	
0x124c:	mov	dword ptr [rip + 0x2dca], eax	; mov dword ptr [0x401c], eax
0x1252:	add	dword ptr [rbp - 4], 1	
0x1256:	mov	eax, dword ptr [rbp - 4]	
0x1259:	cmp	eax, dword ptr [rbp - 0x14]	
0x125c:	jl	0x122a	
0x125e:	jmp	0x128b	
0x1260:	mov	eax, dword ptr [rip + 0x2db6]	; mov eax, dword ptr [0x401c]
0x1266:	mov	esi, eax	
0x1268:	lea	rax, [rip + 0xdee]	; lea rax, ["Global counter: %d"]
0x126f:	mov	rdi, rax	
0x1272:	mov	eax, 0	
0x1277:	call	0x1090	
0x127c:	mov	eax, dword ptr [rip + 0x2d9a]	; mov eax, dword ptr [0x401c]
0x1282:	sub	eax, 1	
0x1285:	mov	dword ptr [rip + 0x2d91], eax	; mov dword ptr [0x401c], eax
0x128b:	mov	eax, dword ptr [rip + 0x2d8b]	; mov eax, dword ptr [0x401c]
0x1291:	test	eax, eax	
0x1293:	jg	0x1260	
0x1295:	nop		
0x1296:	nop		
0x1297:	leave		
0x1298:	ret		
0x1299:	endbr64		
0x129d:	push	rbp	
0x129e:	mov	rbp, rsp	
0x12a1:	sub	rsp, 0x10	
0x12a5:	mov	dword ptr [rbp - 4], edi	
0x12a8:	cmp	dword ptr [rbp - 4], 3	
0x12ac:	je	0x12e4	
0x12ae:	cmp	dword ptr [rbp - 4], 3	
0x12b2:	jg	0x12f5	
0x12b4:	cmp	dword ptr [rbp - 4], 1	
0x12b8:	je	0x12c2	
0x12ba:	cmp	dword ptr [rbp - 4], 2	
0x12be:	je	0x12d3	
0x12c0:	jmp	0x12f5	
0x12c2:	lea	rax, [rip + 0xda8]	; lea rax, ["Option 1 selected"]
0x12c9:	mov	rdi, rax	
0x12cc:	call	0x1070	
0x12d1:	jmp	0x1305	
0x12d3:	lea	rax, [rip + 0xda9]	; lea rax, ["Option 2 selected"]
0x12da:	mov	rdi, rax	
0x12dd:	call	0x1070	
0x12e2:	jmp	0x1305	
0x12e4:	lea	rax, [rip + 0xdaa]	; lea rax, ["Option 3 selected"]
0x12eb:	mov	rdi, rax	
0x12ee:	call	0x1070	
0x12f3:	jmp	0x1305	
0x12f5:	lea	rax, [rip + 0xdab]	; lea rax, ["Invalid option"]
0x12fc:	mov	rdi, rax	
0x12ff:	call	0x1070	
0x1304:	nop		
0x1305:	nop		
0x1306:	leave		
0x1307:	ret		
0x1308:	endbr64		
0x130c:	push	rbp	
0x130d:	mov	rbp, rsp	
0x1310:	mov	dword ptr [rbp - 0x14], edi	
0x1313:	mov	dword ptr [rbp - 0x18], esi	
0x1316:	mov	dword ptr [rbp - 8], 0	
0x131d:	cmp	dword ptr [rbp - 0x14], 0xa	
0x1321:	jle	0x1341	
0x1323:	cmp	dword ptr [rbp - 0x18], 4	
0x1327:	jg	0x1336	
0x1329:	mov	edx, dword ptr [rbp - 0x14]	
0x132c:	mov	eax, dword ptr [rbp - 0x18]	
0x132f:	add	eax, edx	
0x1331:	mov	dword ptr [rbp - 8], eax	
0x1334:	jmp	0x135c	
0x1336:	mov	eax, dword ptr [rbp - 0x14]	
0x1339:	sub	eax, dword ptr [rbp - 0x18]	
0x133c:	mov	dword ptr [rbp - 8], eax	
0x133f:	jmp	0x135c	
0x1341:	mov	dword ptr [rbp - 4], 0	
0x1348:	jmp	0x1354	
0x134a:	mov	eax, dword ptr [rbp - 4]	
0x134d:	add	dword ptr [rbp - 8], eax	
0x1350:	add	dword ptr [rbp - 4], 1	
0x1354:	mov	eax, dword ptr [rbp - 4]	
0x1357:	cmp	eax, dword ptr [rbp - 0x14]	
0x135a:	jl	0x134a	
0x135c:	mov	eax, dword ptr [rbp - 8]	
0x135f:	pop	rbp	
0x1360:	ret		
0x1361:	endbr64		
0x1365:	push	rbp	
0x1366:	mov	rbp, rsp	
0x1369:	sub	rsp, 0x10	
0x136d:	mov	dword ptr [rbp - 4], edi	
0x1370:	cmp	dword ptr [rbp - 4], 1	
0x1374:	jg	0x137d	
0x1376:	mov	eax, 1	
0x137b:	jmp	0x138e	
0x137d:	mov	eax, dword ptr [rbp - 4]	
0x1380:	sub	eax, 1	
0x1383:	mov	edi, eax	
0x1385:	call	0x1361	; call factorial
0x138a:	imul	eax, dword ptr [rbp - 4]	
0x138e:	leave		
0x138f:	ret		
0x1390:	endbr64		
0x1394:	push	rbp	
0x1395:	mov	rbp, rsp	
0x1398:	sub	rsp, 0x20	
0x139c:	mov	qword ptr [rbp - 0x18], rdi	; mov memory[rbp - 0x18], rdi
0x13a0:	mov	rax, qword ptr [rbp - 0x18]	; mov rax, memory[rbp - 0x18]
0x13a4:	mov	esi, 3	
0x13a9:	mov	edi, 2	
0x13ae:	call	rax	
0x13b0:	mov	dword ptr [rbp - 4], eax	
0x13b3:	mov	eax, dword ptr [rbp - 4]	
0x13b6:	mov	esi, eax	
0x13b8:	lea	rax, [rip + 0xcf7]	; lea rax, ["Func ptr result: %d"]
0x13bf:	mov	rdi, rax	
0x13c2:	mov	eax, 0	
0x13c7:	call	0x1090	
0x13cc:	nop		
0x13cd:	leave		
0x13ce:	ret		
0x13cf:	endbr64		
0x13d3:	push	rbp	
0x13d4:	mov	rbp, rsp	
0x13d7:	sub	rsp, 0x20	
0x13db:	mov	rax, qword ptr fs:[0x28]	
0x13e4:	mov	qword ptr [rbp - 8], rax	; mov memory[rbp - 8], rax
0x13e8:	xor	eax, eax	
0x13ea:	mov	dword ptr [rbp - 0x1c], 1	
0x13f1:	mov	dword ptr [rbp - 0x18], 2	
0x13f8:	mov	dword ptr [rbp - 0x14], 0xa	
0x13ff:	mov	dword ptr [rbp - 0x10], 0x14	
0x1406:	mov	dword ptr [rbp - 0xc], 0x1e	
0x140d:	mov	edi, dword ptr [rbp - 0xc]	
0x1410:	mov	esi, dword ptr [rbp - 0x10]	
0x1413:	mov	ecx, dword ptr [rbp - 0x14]	
0x1416:	mov	edx, dword ptr [rbp - 0x18]	
0x1419:	mov	eax, dword ptr [rbp - 0x1c]	
0x141c:	mov	r9d, edi	
0x141f:	mov	r8d, esi	
0x1422:	mov	esi, eax	
0x1424:	lea	rax, [rip + 0xca5]	; lea rax, ["Point: %d %d, Array: %d %d %d"]
0x142b:	mov	rdi, rax	
0x142e:	mov	eax, 0	
0x1433:	call	0x1090	
0x1438:	nop		
0x1439:	mov	rax, qword ptr [rbp - 8]	; mov rax, memory[rbp - 8]
0x143d:	sub	rax, qword ptr fs:[0x28]	
0x1446:	je	0x144d	
0x1448:	call	0x1080	
0x144d:	leave		
0x144e:	ret		
0x144f:	endbr64		
0x1453:	push	rbp	
0x1454:	mov	rbp, rsp	
0x1457:	sub	rsp, 0x10	
0x145b:	mov	dword ptr [rbp - 8], 1	
0x1462:	cmp	dword ptr [rbp - 8], 0	
0x1466:	je	0x1488	
0x1468:	mov	dword ptr [rbp - 4], 2	
0x146f:	mov	eax, dword ptr [rbp - 4]	
0x1472:	mov	esi, eax	
0x1474:	lea	rax, [rip + 0xc74]	; lea rax, ["Inner b: %d"]
0x147b:	mov	rdi, rax	
0x147e:	mov	eax, 0	
0x1483:	call	0x1090	
0x1488:	nop		
0x1489:	leave		
0x148a:	ret		
0x148b:	endbr64		
0x148f:	push	rbp	
0x1490:	mov	rbp, rsp	
0x1493:	sub	rsp, 0x20	
0x1497:	mov	rax, qword ptr fs:[0x28]	
0x14a0:	mov	qword ptr [rbp - 8], rax	; mov memory[rbp - 8], rax
0x14a4:	xor	eax, eax	
0x14a6:	lea	rax, [rbp - 0x20]	
0x14aa:	mov	dword ptr [rax], 0x74736574	
0x14b0:	mov	byte ptr [rax + 4], 0	; mov memory[rax + 4], 0
0x14b4:	lea	rax, [rbp - 0x20]	
0x14b8:	mov	rsi, rax	
0x14bb:	lea	rax, [rip + 0xc3a]	; lea rax, ["Buffer: %s"]
0x14c2:	mov	rdi, rax	
0x14c5:	mov	eax, 0	
0x14ca:	call	0x1090	
0x14cf:	nop		
0x14d0:	mov	rax, qword ptr [rbp - 8]	; mov rax, memory[rbp - 8]
0x14d4:	sub	rax, qword ptr fs:[0x28]	
0x14dd:	je	0x14e4	
0x14df:	call	0x1080	
0x14e4:	leave		
0x14e5:	ret		
0x14e6:	endbr64		
0x14ea:	push	rbp	
0x14eb:	mov	rbp, rsp	
0x14ee:	nop		
0x14ef:	pop	rbp	
0x14f0:	ret		
0x14f1:	endbr64		
0x14f5:	push	rbp	
0x14f6:	mov	rbp, rsp	
0x14f9:	mov	eax, 0x2a	
0x14fe:	pop	rbp	
0x14ff:	ret		
0x1500:	endbr64		
0x1504:	push	rbp	
0x1505:	mov	rbp, rsp	
0x1508:	nop		
0x1509:	pop	rbp	
0x150a:	ret		
0x150b:	endbr64		
0x150f:	push	rbp	
0x1510:	mov	rbp, rsp	
0x1513:	sub	rsp, 0x20	
0x1517:	mov	dword ptr [rbp - 0x14], edi	
0x151a:	mov	qword ptr [rbp - 0x20], rsi	; mov memory[rbp - 0x20], rsi
0x151e:	lea	rax, [rip + 0xbe3]	; lea rax, ["Binary Inspector Test Program"]
0x1525:	mov	rdi, rax	
0x1528:	call	0x1070	
0x152d:	mov	rax, qword ptr [rip + 0x2adc]	; mov rax, memory[0x4010]
0x1534:	mov	rsi, rax	
0x1537:	lea	rax, [rip + 0xbe8]	; lea rax, ["Global message: %s"]
0x153e:	mov	rdi, rax	
0x1541:	mov	eax, 0	
0x1546:	call	0x1090	
0x154b:	mov	esi, 3	
0x1550:	mov	edi, 5	
0x1555:	call	0x1189	; call add_numbers
0x155a:	mov	dword ptr [rbp - 0x10], eax	
0x155d:	mov	eax, dword ptr [rbp - 0x10]	
0x1560:	mov	esi, eax	
0x1562:	lea	rax, [rip + 0xbd1]	; lea rax, ["Sum: %d"]
0x1569:	mov	rdi, rax	
0x156c:	mov	eax, 0	
0x1571:	call	0x1090	
0x1576:	mov	edi, 0xa	
0x157b:	call	0x11a1	; call check_number
0x1580:	mov	edi, 0xfffffffb	
0x1585:	call	0x11a1	; call check_number
0x158a:	mov	edi, 0	
0x158f:	call	0x11a1	; call check_number
0x1594:	mov	edi, 3	
0x1599:	call	0x1212	; call print_loop
0x159e:	mov	edi, 2	
0x15a3:	call	0x1299	; call process_choice
0x15a8:	mov	edi, 5	
0x15ad:	call	0x1299	; call process_choice
0x15b2:	mov	esi, 3	
0x15b7:	mov	edi, 0xf	
0x15bc:	call	0x1308	; call complex_logic
0x15c1:	mov	dword ptr [rbp - 0xc], eax	
0x15c4:	mov	eax, dword ptr [rbp - 0xc]	
0x15c7:	mov	esi, eax	
0x15c9:	lea	rax, [rip + 0xb73]	; lea rax, ["Complex result: %d"]
0x15d0:	mov	rdi, rax	
0x15d3:	mov	eax, 0	
0x15d8:	call	0x1090	
0x15dd:	mov	edi, 5	
0x15e2:	call	0x1361	; call factorial
0x15e7:	mov	dword ptr [rbp - 8], eax	
0x15ea:	mov	eax, dword ptr [rbp - 8]	
0x15ed:	mov	esi, eax	
0x15ef:	lea	rax, [rip + 0xb61]	; lea rax, ["Factorial(5): %d"]
0x15f6:	mov	rdi, rax	
0x15f9:	mov	eax, 0	
0x15fe:	call	0x1090	
0x1603:	lea	rax, [rip - 0x481]	; lea rax, [0x160a - 0x481]
0x160a:	mov	rdi, rax	
0x160d:	call	0x1390	; call call_func_ptr
0x1612:	mov	eax, 0	
0x1617:	call	0x13cf	; call struct_test
0x161c:	mov	eax, 0	
0x1621:	call	0x144f	; call local_var_test
0x1626:	mov	eax, 0	
0x162b:	call	0x148b	; call string_test
0x1630:	mov	eax, 0	
0x1635:	call	0x14e6	; call empty_function
0x163a:	mov	eax, 0	
0x163f:	call	0x14f1	; call return_only
0x1644:	mov	dword ptr [rbp - 4], eax	
0x1647:	mov	eax, dword ptr [rbp - 4]	
0x164a:	mov	esi, eax	
0x164c:	lea	rax, [rip + 0xb16]	; lea rax, ["Return-only: %d"]
0x1653:	mov	rdi, rax	
0x1656:	mov	eax, 0	
0x165b:	call	0x1090	
0x1660:	mov	eax, 0	
0x1665:	call	0x1500	; call unreachable_code
0x166a:	cmp	dword ptr [rbp - 0x14], 1	
0x166e:	jle	0x1692	
0x1670:	mov	rax, qword ptr [rbp - 0x20]	; mov rax, memory[rbp - 0x20]
0x1674:	add	rax, 8	
0x1678:	mov	rax, qword ptr [rax]	; mov rax, memory[rax]
0x167b:	mov	rsi, rax	
0x167e:	lea	rax, [rip + 0xaf5]	; lea rax, ["First argument: %s"]
0x1685:	mov	rdi, rax	
0x1688:	mov	eax, 0	
0x168d:	call	0x1090	
0x1692:	mov	eax, 0	
0x1697:	leave		
0x1698:	ret		
