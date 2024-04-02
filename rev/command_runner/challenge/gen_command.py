from PIL import Image, ImageDraw, ImageFont
import sys
import string
import zlib
import os

if len(sys.argv) < 3:
    print("How to use: python3 gen_command.py {command} {output_filename} {solvable}")
    exit(0)

CHARSET = string.ascii_letters + string.digits + string.punctuation

data = [ [[0] * 16 for j in range(16)] for i in range(128) ]

for ch in CHARSET:
    img = Image.new("1", (16, 16), 0)
    draw = ImageDraw.Draw(img)

    fnt = ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 16)
    draw.text((2, 0), ch, font=fnt, fill=1)

    res = img.tobytes()
    for i in range(0, 32, 2):
        d = int.from_bytes(res[i:i+2], 'big')
        data[ord(ch)][i >> 1] = list(map(int, f"{d:016b}"))

command = sys.argv[1]
img = Image.new("RGB", (16 * len(command), 16), (255, 255, 255))

for idx, ch in enumerate(command):
    if ch == ' ':
        continue
    
    char_data = data[ord(ch)]
    for j in range(16):
        for k in range(16):
            if char_data[j][k]:
                img.putpixel( (idx * 16 + k, j), (0, 0, 0) )

img.save("temp.png")
data = open('temp.png', 'rb').read()
os.remove('temp.png')
to_out = open(sys.argv[2], 'wb')

to_out.write(data[:8])
idx = 8
idat = b''

def recompress_idat(idat):
    raw = zlib.decompress(idat)
    compressobj = zlib.compressobj(strategy=zlib.Z_FIXED)
    res = compressobj.compress(raw)
    res += compressobj.flush()
    res = bytearray(res)

    if len(sys.argv) > 3:
        res[2] ^= 0b100 # make btype from 1 to 3

    ret = b''
    while len(res) > 0:
        ln = 0x10000 if len(res) >= 0x10000 else len(res)
        ret += ln.to_bytes(4, 'big')
        ret += b'IDAT'
        ret += res[:ln]
        ret += zlib.crc32(res[:ln]).to_bytes(4, 'big')

        res = res[ln:]
    return ret

while True:
    ln = int.from_bytes(data[idx:idx+4], 'big')
    if data[idx+4:idx+8] == b'IDAT':
        idat += data[idx+8:idx+8+ln]
    elif data[idx+4:idx+8] in b'IHDR':
        to_out.write(data[idx:idx+ln+12])
    elif data[idx+4:idx+8] == b'IEND':
        dump = recompress_idat(idat)
        to_out.write(dump)
        to_out.write(data[idx:idx+ln+12])
        break
    else:
        print(data[idx+4:idx+8])
        exit(0)
    
    idx += 12 + ln

to_out.close()
