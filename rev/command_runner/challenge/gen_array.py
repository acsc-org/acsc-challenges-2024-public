from PIL import Image, ImageDraw, ImageFont
import string

CHARSET = string.ascii_letters + string.digits + string.punctuation

data = [ [0 for _ in range(32)] for _ in range(128) ]

for ch in CHARSET:
    img = Image.new("1", (16, 16), 0)
    draw = ImageDraw.Draw(img)

    fnt = ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 16)
    draw.text((2, 0), ch, font=fnt, fill=1)

    res = img.tobytes()
    data[ord(ch)] = list(res)

for i in range(128):
    print(str(data[i]).replace('[', '{').replace(']', '}') + ',')