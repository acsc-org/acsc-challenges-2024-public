table = []
for c in range(0x100):
    if ord('A') <= c <= ord('Z'):
        table.append(ord('A') + ((c - ord('A') + 13) % 26))
    elif ord('a') <= c <= ord('z'):
        table.append(ord('a') + ((c - ord('a') + 13) % 26))
    else:
        table.append(c)

for i in range(0x100):
    if i % 16 == 0:
        print('  "', end='')
    print(f"\\x{table[i]:02x}", end='')
    if i % 16 == 15:
        print('"')
