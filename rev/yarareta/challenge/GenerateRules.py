import random

random.seed(0xAC5C)

def genRangeSamples(val):
    samples = []
    if val - 1 >= 0:
        samples.append(val - 1)
    if val + 1 <= 255:
        samples.append(val + 1)

    data = set(range(256))
    data.remove(val)
    # remove the elements of samples from data
    for sample in samples:
        data.remove(sample)

    if 0 in data:
        data.remove(0)
    if 0xff in data:
        data.remove(0xff)

    for _ in range(32 - len(samples)):
        rand_val = random.choice(list(data))
        samples.append(rand_val)
        data.remove(rand_val)
    random.shuffle(samples)
    range_samples = []
    for i in range(len(samples)):
        if samples[i] > val:
            range_samples.append((samples[i], 0xff))
        elif samples[i] < val:
            range_samples.append((0x00, samples[i]))
    return range_samples

def getRules(key):
    rules = []
    for val in key:
        rangeSamples = genRangeSamples(val)
        rules.append(rangeSamples)
    for i in range(len(rules[0])):
        regex = ''
        for k in range(len(rules)):
            regex += f'[^\\x{rules[k][i][0]:02x}-\\x{rules[k][i][1]:02x}]' 
        print('acsc.check(/^' + regex + '/)')

def main():
    encFlagKey = b'\x98\xff\xf9\xd4\x8c\x07\x86\x25\x05\x1b\xf1\x24\xd8\xb8\x91\x4c'
    getRules(encFlagKey)

if __name__ == '__main__':
    main()
