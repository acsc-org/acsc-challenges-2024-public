def interpret(bcode = []):
    PC = 4
    LR = 5
    FLAG = 13
    SP = 14
    BP = 15

    def getMem(mem, addr, size):
        if addr + size > 0x5000:
            print(f'invalid mem get : {hex(addr)} {hex(size)}')
        return int.from_bytes(mem[addr : addr + size],'little')
    def setMem(mem, addr, size, val):
        if addr + size > 0x5000:
            print(f'invalid mem set : {hex(addr)} {hex(size)}')
        val = val & ((1 << (size * 8)) - 1)
        v = int.to_bytes(val, size, 'little')
        for i in range(size):
            mem[addr + i] = v[i]
    def getOpcode(mem, addr, size):
        if addr < 0x2000 or addr + size > 0x3000:
            print(f'invalid mem get : {hex(addr)} {hex(size)}')
        return int.from_bytes(bcode[addr - 0x2000 : addr - 0x2000 + size],'little')
    if type(bcode) == bytes:
        bcode = list(bcode)
    regs = [0 for i in range(0x10)]
    regs[PC]  = 0x2000             #pc
    regs[LR]  = 0xffffffffffffffff #lr
    regs[FLAG] = 0                 #flag
    regs[SP] = 0x4000              #sp
    regs[BP] = 0x4000              #bp
    bcode = bcode + [0 for i in range(0x1000 - len(bcode))]
    mem = [[0 for i in range(0x1000)] + \
           [0 for i in range(0x1000)] + \
           bcode + \
           [0 for i in range(0x1000)] + \
           [0 for i in range(0x1000)]
    while True:
        opcode = getOpcode(mem, regs[PC], 1)
        if (opcode & 0xf0) == 0 and (opcode & 0x8) == 0x8:
            size = (opcode & 0x7) + 1
            v = getOpcode(mem, regs[PC] + 1, size)
            regs[PC] += 1 + size
            regs[SP] -= size
            setMem(mem, regs[SP], size, v)
        elif (opcode & 0xf0) == 0x10:
            size = (opcode & 0x7) + 1
            r = getOpcode(mem, regs[PC] + 1, 1) & 0xf
            regs[PC] += 2
            if r in (PC, LR):
                print(f'invalid opcode at {hex(regs[PC])}')
                return mem, regs
            if (opcode & 0x8) == 0:
                regs[r] = getMem(mem, regs[SP], size)
                regs[SP] += size
            else:
                regs[SP] -= size
                setMem(mem, regs[SP], size, regs[r])
        elif (opcode & 0xf0) == 0x20:
            size = (opcode & 0x7) + 1
            r = getOpcode(mem, regs[PC] + 1, 1)
            regs[PC] += 2
            r1 = r & 0xf
            r2 = r >> 4
            if r1 in (PC, LR) or r2 in (PC, LR):
                print(f'invalid opcode at {hex(regs[PC])}')
                return mem, regs
            if (opcode & 0x8) == 0:
                regs[r1] = getMem(mem, regs[r2], size)
            else:
                setMem(mem, regs[r1], size, regs[r2])
        elif (opcode & 0xf0) == 0x30:
            size = (opcode & 0x7) + 1
            r = getOpcode(mem, regs[PC] + 1, 1) & 0xf
            v = getOpcode(mem, regs[PC] + 2, size)
            regs[PC] += 2 + size
            if r in (PC, LR):
                print(f'invalid opcode at {hex(regs[PC])}')
                return mem, regs
            if (opcode & 0x8) == 0:
                regs[r] = v
            else:
                setMem(mem, regs[r], size, v)
        elif (opcode & 0xf0) == 0x40:
            if (opcode & 0x8) == 0x8:
                '''
                r = getOpcode(mem, regs[PC] + 1, 1) & 0xf
                regs[PC] += 2
                dst = regs[r]
                '''
                print(f'invalid opcode at {hex(regs[PC])}')
                return mem, regs
            else:
                dst = getOpcode(mem, regs[PC] + 1, 2)
                if dst >= 0x8000:
                    dst -= 0x10000
                regs[PC] += 3
                dst += regs[PC]
            if (opcode & 0xf) == 0:
                regs[PC] = dst
            elif (opcode & 0xf) == 1:
                regs[SP] -= 6
                setMem(mem, regs[SP], 6, regs[LR])  #push lr
                regs[SP] -= 6
                setMem(mem, regs[SP], 6, regs[BP])  #push bp
                regs[BP] = regs[SP]
                regs[LR] = regs[PC]
                regs[PC] = dst
            elif (opcode & 0xf) == 2 and (regs[FLAG] & 4) == 4:
                regs[PC] = dst
            elif (opcode & 0xf) == 3 and (regs[FLAG] & 3) != 0:
                regs[PC] = dst
            elif (opcode & 0xf) == 4 and (regs[FLAG] & 1) == 1:
                regs[PC] = dst
            elif (opcode & 0xf) == 5 and (regs[FLAG] & 1) == 0:
                regs[PC] = dst
            elif (opcode & 0xf) == 6 and (regs[FLAG] & 5) != 0:
                regs[PC] = dst
            elif (opcode & 0xf) == 7 and (regs[FLAG] & 2) == 2:
                regs[PC] = dst
        elif (opcode & 0xf0) == 0x50 and (opcode & 0xf) <= 0xa:
            r = getOpcode(mem, regs[PC] + 1, 1)
            regs[PC] += 2
            r1 = r & 0xf
            r2 = r >> 4
            if r1 in (PC, LR) or r2 in (PC, LR):
                print(f'invalid opcode at {hex(regs[PC])}')
                return mem, regs
            if (opcode & 0xf) == 0:
                regs[r1] = (regs[r1] + regs[r2]) & 0xffffffffffffffff
            elif (opcode & 0xf) == 1:
                regs[r1] = (regs[r1] - regs[r2]) & 0xffffffffffffffff
                if regs[r1] < 0:
                    regs[r1] += 0x10000000000000000
            elif (opcode & 0xf) == 2:
                regs[r1] = (regs[r1] * regs[r2]) & 0xffffffffffffffff
            elif (opcode & 0xf) == 3:
                regs[r1] = (regs[r1] // regs[r2]) & 0xffffffffffffffff
            elif (opcode & 0xf) == 4:
                regs[r1] = (regs[r1] & regs[r2]) & 0xffffffffffffffff
            elif (opcode & 0xf) == 5:
                regs[r1] = (regs[r1] | regs[r2]) & 0xffffffffffffffff
            elif (opcode & 0xf) == 6:
                regs[r1] = (regs[r1] ^ regs[r2]) & 0xffffffffffffffff
            elif (opcode & 0xf) == 7:
                regs[r1] = (regs[r1] >> (regs[r2] & 0x3f)) & 0xffffffffffffffff
            elif (opcode & 0xf) == 8:
                regs[r1] = (regs[r1] << (regs[r2] & 0x3f)) & 0xffffffffffffffff
            elif (opcode & 0xf) == 9:
                regs[r1] = regs[r2]
            elif (opcode & 0xf) == 10:
                flag = 0
                if regs[r1] == regs[r2]:
                    flag |= 1
                if regs[r1] > regs[r2]:
                    flag |= 2
                if regs[r1] < regs[r2]:
                    flag |= 4
                regs[FLAG] = flag
        elif (opcode & 0xf0) == 0xf0 and (opcode & 0xf) >= 0xd:
            if opcode == 0xfd:
                regs[SP] = regs[BP]
                regs[BP] = getMem(mem, regs[SP], 6)
                regs[SP] += 6
                regs[PC] = regs[LR]
                regs[LR] = getMem(mem, regs[SP], 6)
                regs[SP] += 6
            elif opcode == 0xfe:
                regs[PC] += 1
                input('invoke')
            elif opcode == 0xff:
                regs[PC] += 1
                return mem, regs
        else:
            print(f'invalid opcode at {hex(regs[PC])}')
            return mem, regs
