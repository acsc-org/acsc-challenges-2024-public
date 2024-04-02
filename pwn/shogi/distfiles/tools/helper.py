from pwn import *

###Util
def makeMove(r, move):
    '''
    r    : pwntool remote instance (r = remote(IP, PORT))
    move : the move to play, see explanation below for details
    '''
    ### Some examples on how to construct moves to pass to the makeMove function
    #   1. To move a piece from <src_pos> to <dst_pos>, you are required to specify the two positions, for instance
    #      e.g. ((1,9),(1,8))
    #   2. When promoting is possible (and not mandatory) after moving, you must include the decision as the third entry of move tuple
    #      e.g. ((5,4),(5,3),'yes') / ((5,4),(5,3),'no')
    #   3. To drop a piece on the board, specify '打' (drop) + the piece to drop (e.g. '歩') along with the position to drop it
    #      e.g. ('打歩',(5,4))
    #   4. To surrender, send this as your move
    #      e.g. ('投了',)
    kanjimap = [c.encode() for c in ['','一','二','三','四','五','六','七','八','九']]
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
