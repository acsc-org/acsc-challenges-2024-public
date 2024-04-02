from PIL import Image
import zlib

img = Image.new("RGB", (50, 50), (128,128,128))
img.save("test2.png")

data = open('test2.png', 'rb').read()
to_out = open('test2_fixed.png', 'wb')

to_out.write(data[:8])
idx = 8
idat = b''

def recompress_idat(idat):
    raw = zlib.decompress(idat)
    print(raw)
    compressobj = zlib.compressobj(strategy=zlib.Z_FIXED)
    res = compressobj.compress(raw)
    res += compressobj.flush()

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

