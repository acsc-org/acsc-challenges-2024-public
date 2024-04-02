# Command Runner

This challenge is a find-needle-in-haystack type of challenge.

If you first read a decompiled code, you may notice that there are PNG-related header values; "IHDR", "IDAT" and so on.
But you also may notice it is not possible to put any PNG files. There are too many assertions (if-then-exit)!

So the participant needs to first figure out what assertions are there in the binary,
and mostly the most important stuffs are those:

- `height` must be 16, and `width` must satisfy `width % 16 == 0` and `0 < width < 240`.
- `bitdepth` must be 8, and `colortype` must be 2 (RGB).
- There is no filter/interlace.
- `btype` of IDAT data must be either 1 or 3.

With `zlib.compressobj` in Python, you can make `IDAT` dat with `btype=1` by using `strategy=zlib.Z_FIXED`. (https://docs.python.org/3/library/zlib.html)

After this, you also may find there's data for font recognition. You can directly use them to generate your own command PNG file.
However, even with that, it's not possible to run your own command. For example, if you put `ls`, the binary will execute `l`.

The last part of this challenge is to find that the font data is modified when `btype` is 1.
If you set `btype` to 3, without changing any other data, you can run your command successfully.