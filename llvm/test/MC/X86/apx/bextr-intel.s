# RUN: llvm-mc -triple x86_64 -x86-asm-syntax=intel -output-asm-variant=1 --show-encoding %s | FileCheck %s

# CHECK: {nf}	bextr	r10d, edx, ecx
# CHECK: encoding: [0x62,0x72,0x74,0x0c,0xf7,0xd2]
         {nf}	bextr	r10d, edx, ecx

# CHECK: {evex}	bextr	r10d, edx, ecx
# CHECK: encoding: [0x62,0x72,0x74,0x08,0xf7,0xd2]
         {evex}	bextr	r10d, edx, ecx

# CHECK: {nf}	bextr	edx, dword ptr [rax + 4*rbx + 123], ecx
# CHECK: encoding: [0x62,0xf2,0x74,0x0c,0xf7,0x54,0x98,0x7b]
         {nf}	bextr	edx, dword ptr [rax + 4*rbx + 123], ecx

# CHECK: {evex}	bextr	edx, dword ptr [rax + 4*rbx + 123], ecx
# CHECK: encoding: [0x62,0xf2,0x74,0x08,0xf7,0x54,0x98,0x7b]
         {evex}	bextr	edx, dword ptr [rax + 4*rbx + 123], ecx

# CHECK: {nf}	bextr	r11, r15, r9
# CHECK: encoding: [0x62,0x52,0xb4,0x0c,0xf7,0xdf]
         {nf}	bextr	r11, r15, r9

# CHECK: {evex}	bextr	r11, r15, r9
# CHECK: encoding: [0x62,0x52,0xb4,0x08,0xf7,0xdf]
         {evex}	bextr	r11, r15, r9

# CHECK: {nf}	bextr	r15, qword ptr [rax + 4*rbx + 123], r9
# CHECK: encoding: [0x62,0x72,0xb4,0x0c,0xf7,0x7c,0x98,0x7b]
         {nf}	bextr	r15, qword ptr [rax + 4*rbx + 123], r9

# CHECK: {evex}	bextr	r15, qword ptr [rax + 4*rbx + 123], r9
# CHECK: encoding: [0x62,0x72,0xb4,0x08,0xf7,0x7c,0x98,0x7b]
         {evex}	bextr	r15, qword ptr [rax + 4*rbx + 123], r9

# CHECK: bextr	r26d, r22d, r18d
# CHECK: encoding: [0x62,0x6a,0x6c,0x00,0xf7,0xd6]
         bextr	r26d, r22d, r18d

# CHECK: bextr	r22d, dword ptr [r28 + 4*r29 + 291], r18d
# CHECK: encoding: [0x62,0x8a,0x68,0x00,0xf7,0xb4,0xac,0x23,0x01,0x00,0x00]
         bextr	r22d, dword ptr [r28 + 4*r29 + 291], r18d

# CHECK: bextr	r27, r23, r19
# CHECK: encoding: [0x62,0x6a,0xe4,0x00,0xf7,0xdf]
         bextr	r27, r23, r19

# CHECK: bextr	r23, qword ptr [r28 + 4*r29 + 291], r19
# CHECK: encoding: [0x62,0x8a,0xe0,0x00,0xf7,0xbc,0xac,0x23,0x01,0x00,0x00]
         bextr	r23, qword ptr [r28 + 4*r29 + 291], r19
