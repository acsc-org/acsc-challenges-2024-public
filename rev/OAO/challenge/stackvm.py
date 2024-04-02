import ctypes

class StackVM:
    def __init__(self):
        self.stack = []
        self.mem = [162, 86, 33, 109, 24, 9, 177, 75, 106, 137, 52, 218, 41, 214, 96, 241]+[0] * 0x100 #secret key to get flag
    def push(self, val):
        self.stack.append(val)
        
    def pop(self):
        if len(self.stack) < 1:
            return None
        return self.stack.pop()
    
    def execute(self, bytecode):
        ip = 0
        while ip < len(bytecode):
            opcode = bytecode[ip]
            if opcode == 1:
                ip += 1
                val = bytecode[ip]
                self.push(val)
            elif opcode == 2:
                a = self.pop()
                b = self.pop()
                self.push(ctypes.c_uint32(a + b).value)
            elif opcode == 3:
                a = self.pop()
                b = self.pop()
                self.push(ctypes.c_uint32(b - a).value)
            elif opcode == 4:
                a = self.pop()
                b = self.pop()
                self.push(a * b)
            elif opcode == 5:
                a = self.pop()
                b = self.pop()
                if a != 0:
                    self.push(b / a)
                else:
                    print("Error: Division by zero!")
                    return
            elif opcode == 6:
                print(self.pop())
            elif opcode == 7:
                idx = self.pop()
                value = self.pop()
                self.mem[idx] = value
            elif opcode == 8:
                idx = self.pop()
                value = self.mem[idx]
                self.push(value)
            elif opcode == 9:
                a = self.pop()
                b = self.pop()
                self.push(b%a)
            elif opcode == 10:
                a = self.pop()
                b = self.pop()
                self.push(b^a)
            elif opcode == 11:
                a = self.pop()
                b = self.pop()
                self.push((b << a)&0xffffffff)
            elif opcode == 12:
                a = self.pop()
                b = self.pop()
                self.push(b >> a)
            ip += 1

class Compiler:
    def __init__(self):
        self.bytecode = []
        
    def compile(self, expression):
        tokens = expression.split()
        for token in tokens:
            if token.isdigit():
                self.bytecode.append(1)
                self.bytecode.append(int(token))
            elif token == "+":
                self.bytecode.append(2)
            elif token == "-":
                self.bytecode.append(3)
            elif token == "*":
                self.bytecode.append(4)
            elif token == "/":
                self.bytecode.append(5)
            elif token == ".":
                self.bytecode.append(6)
            elif token == "S":
                self.bytecode.append(7)
            elif token == "L":
                self.bytecode.append(8)
            elif token == "%":
                self.bytecode.append(9)
            elif token == "^":
                self.bytecode.append(10)
            elif token == "<<":
                self.bytecode.append(11)
            elif token == ">>":
                self.bytecode.append(12)
        return self.bytecode

compiler = Compiler()
bytecode = compiler.compile("0 L 363642534 + 0 S 1 L 219364268 + 1 S 2 L 3299433934 + 2 S 3 L 3800776298 + 3 S 4 L 2541584171 + 4 S 5 L 1111656278 + 5 S 6 L 867454903 + 6 S 7 L 1751323194 + 7 S 8 L 2751880888 + 8 S 9 L 4002977119 + 9 S 10 L 1068563059 + 10 S 11 L 3494479573 + 11 S 12 L 195306073 + 12 S 13 L 3804143320 + 13 S 14 L 2431519749 + 14 S 15 L 1662725893 + 15 S 0 L 16 S 1 L 17 S 2 L 18 S 3 L 19 S 4 L 20 S 5 L 21 S 6 L 22 S 7 L 23 S 8 L 24 S 9 L 25 S 10 L 26 S 11 L 27 S 12 L 28 S 13 L 29 S 14 L 30 S 15 L 31 S 25 L 0 S 21 L 1 S 17 L 2 S 26 L 3 S 28 L 4 S 30 L 5 S 20 L 6 S 22 L 7 S 19 L 8 S 18 L 9 S 24 L 10 S 23 L 11 S 29 L 12 S 27 L 13 S 16 L 14 S 31 L 15 S 0 L 16 S 1 L 17 S 2 L 18 S 3 L 19 S 4 L 20 S 5 L 21 S 6 L 22 S 7 L 23 S 8 L 24 S 9 L 25 S 10 L 26 S 11 L 27 S 12 L 28 S 13 L 29 S 14 L 30 S 15 L 31 S 28 L 0 S 21 L 1 S 29 L 2 S 26 L 3 S 25 L 4 S 23 L 5 S 19 L 6 S 18 L 7 S 22 L 8 S 30 L 9 S 17 L 10 S 16 L 11 S 24 L 12 S 27 L 13 S 20 L 14 S 31 L 15 S 0 L 16 S 1 L 17 S 2 L 18 S 3 L 19 S 4 L 20 S 5 L 21 S 6 L 22 S 7 L 23 S 8 L 24 S 9 L 25 S 10 L 26 S 11 L 27 S 12 L 28 S 13 L 29 S 14 L 30 S 15 L 31 S 19 L 0 S 29 L 1 S 18 L 2 S 16 L 3 S 28 L 4 S 30 L 5 S 27 L 6 S 20 L 7 S 25 L 8 S 21 L 9 S 22 L 10 S 26 L 11 S 31 L 12 S 17 L 13 S 23 L 14 S 24 L 15 S 0 L 16 S 1 L 17 S 2 L 18 S 3 L 19 S 4 L 20 S 5 L 21 S 6 L 22 S 7 L 23 S 8 L 24 S 9 L 25 S 10 L 26 S 11 L 27 S 12 L 28 S 13 L 29 S 14 L 30 S 15 L 31 S 24 L 0 S 19 L 1 S 21 L 2 S 28 L 3 S 31 L 4 S 17 L 5 S 18 L 6 S 26 L 7 S 16 L 8 S 20 L 9 S 23 L 10 S 25 L 11 S 27 L 12 S 22 L 13 S 30 L 14 S 29 L 15 S 0 L 486169081 + 0 S 1 L 3621734860 + 1 S 2 L 2867016779 + 2 S 3 L 1927106163 + 3 S 4 L 3191867880 + 4 S 5 L 1672442276 + 5 S 6 L 1216586267 + 6 S 7 L 614568690 + 7 S 8 L 4093860384 + 8 S 9 L 2463816567 + 9 S 10 L 674998233 + 10 S 11 L 1177158100 + 11 S 12 L 4145386944 + 12 S 13 L 2597560477 + 13 S 14 L 3373742385 + 14 S 15 L 539941070 + 15 S 0 L 4009682443 ^ 0 S 1 L 4009682443 ^ 1 S 2 L 4009682443 ^ 2 S 3 L 4009682443 ^ 3 S 4 L 4009682443 ^ 4 S 5 L 4009682443 ^ 5 S 6 L 4009682443 ^ 6 S 7 L 4009682443 ^ 7 S 8 L 4009682443 ^ 8 S 9 L 4009682443 ^ 9 S 10 L 4009682443 ^ 10 S 11 L 4009682443 ^ 11 S 12 L 4009682443 ^ 12 S 13 L 4009682443 ^ 13 S 14 L 4009682443 ^ 14 S 15 L 4009682443 ^ 15 S 0 L 915437998 ^ 0 S 1 L 915437998 ^ 1 S 2 L 915437998 ^ 2 S 3 L 915437998 ^ 3 S 4 L 915437998 ^ 4 S 5 L 915437998 ^ 5 S 6 L 915437998 ^ 6 S 7 L 915437998 ^ 7 S 8 L 915437998 ^ 8 S 9 L 915437998 ^ 9 S 10 L 915437998 ^ 10 S 11 L 915437998 ^ 11 S 12 L 915437998 ^ 12 S 13 L 915437998 ^ 13 S 14 L 915437998 ^ 14 S 15 L 915437998 ^ 15 S 0 L 24 << 1 L 8 >> + 16 S 1 L 24 << 2 L 8 >> + 17 S 2 L 24 << 3 L 8 >> + 18 S 3 L 24 << 4 L 8 >> + 19 S 4 L 24 << 5 L 8 >> + 20 S 5 L 24 << 6 L 8 >> + 21 S 6 L 24 << 7 L 8 >> + 22 S 7 L 24 << 8 L 8 >> + 23 S 8 L 24 << 9 L 8 >> + 24 S 9 L 24 << 10 L 8 >> + 25 S 10 L 24 << 11 L 8 >> + 26 S 11 L 24 << 12 L 8 >> + 27 S 12 L 24 << 13 L 8 >> + 28 S 13 L 24 << 14 L 8 >> + 29 S 14 L 24 << 15 L 8 >> + 30 S 15 L 24 << 0 L 8 >> + 31 S 16 L 0 S 17 L 1 S 18 L 2 S 19 L 3 S 20 L 4 S 21 L 5 S 22 L 6 S 23 L 7 S 24 L 8 S 25 L 9 S 26 L 10 S 27 L 11 S 28 L 12 S 29 L 13 S 30 L 14 S 31 L 15 S 0 L 30 << 1 L 2 >> + 16 S 1 L 30 << 2 L 2 >> + 17 S 2 L 30 << 3 L 2 >> + 18 S 3 L 30 << 4 L 2 >> + 19 S 4 L 30 << 5 L 2 >> + 20 S 5 L 30 << 6 L 2 >> + 21 S 6 L 30 << 7 L 2 >> + 22 S 7 L 30 << 8 L 2 >> + 23 S 8 L 30 << 9 L 2 >> + 24 S 9 L 30 << 10 L 2 >> + 25 S 10 L 30 << 11 L 2 >> + 26 S 11 L 30 << 12 L 2 >> + 27 S 12 L 30 << 13 L 2 >> + 28 S 13 L 30 << 14 L 2 >> + 29 S 14 L 30 << 15 L 2 >> + 30 S 15 L 30 << 0 L 2 >> + 31 S 16 L 0 S 17 L 1 S 18 L 2 S 19 L 3 S 20 L 4 S 21 L 5 S 22 L 6 S 23 L 7 S 24 L 8 S 25 L 9 S 26 L 10 S 27 L 11 S 28 L 12 S 29 L 13 S 30 L 14 S 31 L 15 S 0 L 16 S 1 L 17 S 2 L 18 S 3 L 19 S 4 L 20 S 5 L 21 S 6 L 22 S 7 L 23 S 8 L 24 S 9 L 25 S 10 L 26 S 11 L 27 S 12 L 28 S 13 L 29 S 14 L 30 S 15 L 31 S 29 L 0 S 24 L 1 S 31 L 2 S 30 L 3 S 28 L 4 S 17 L 5 S 22 L 6 S 26 L 7 S 21 L 8 S 18 L 9 S 16 L 10 S 19 L 11 S 20 L 12 S 23 L 13 S 25 L 14 S 27 L 15 S 0 L 2504946451 + 0 S 1 L 3848067259 + 1 S 2 L 1222834795 + 2 S 3 L 1611833351 + 3 S 4 L 2988863148 + 4 S 5 L 2070374490 + 5 S 6 L 1070257725 + 6 S 7 L 2208312286 + 7 S 8 L 3139318555 + 8 S 9 L 3344777180 + 9 S 10 L 426414579 + 10 S 11 L 1153058906 + 11 S 12 L 2162575135 + 12 S 13 L 29754151 + 13 S 14 L 3933902725 + 14 S 15 L 797055763 + 15 S 0 L 1132855419 ^ 0 S 1 L 1132855419 ^ 1 S 2 L 1132855419 ^ 2 S 3 L 1132855419 ^ 3 S 4 L 1132855419 ^ 4 S 5 L 1132855419 ^ 5 S 6 L 1132855419 ^ 6 S 7 L 1132855419 ^ 7 S 8 L 1132855419 ^ 8 S 9 L 1132855419 ^ 9 S 10 L 1132855419 ^ 10 S 11 L 1132855419 ^ 11 S 12 L 1132855419 ^ 12 S 13 L 1132855419 ^ 13 S 14 L 1132855419 ^ 14 S 15 L 1132855419 ^ 15 S 0 L 2479975805 ^ 0 S 1 L 2479975805 ^ 1 S 2 L 2479975805 ^ 2 S 3 L 2479975805 ^ 3 S 4 L 2479975805 ^ 4 S 5 L 2479975805 ^ 5 S 6 L 2479975805 ^ 6 S 7 L 2479975805 ^ 7 S 8 L 2479975805 ^ 8 S 9 L 2479975805 ^ 9 S 10 L 2479975805 ^ 10 S 11 L 2479975805 ^ 11 S 12 L 2479975805 ^ 12 S 13 L 2479975805 ^ 13 S 14 L 2479975805 ^ 14 S 15 L 2479975805 ^ 15 S 0 L 25 << 1 L 7 >> + 16 S 1 L 25 << 2 L 7 >> + 17 S 2 L 25 << 3 L 7 >> + 18 S 3 L 25 << 4 L 7 >> + 19 S 4 L 25 << 5 L 7 >> + 20 S 5 L 25 << 6 L 7 >> + 21 S 6 L 25 << 7 L 7 >> + 22 S 7 L 25 << 8 L 7 >> + 23 S 8 L 25 << 9 L 7 >> + 24 S 9 L 25 << 10 L 7 >> + 25 S 10 L 25 << 11 L 7 >> + 26 S 11 L 25 << 12 L 7 >> + 27 S 12 L 25 << 13 L 7 >> + 28 S 13 L 25 << 14 L 7 >> + 29 S 14 L 25 << 15 L 7 >> + 30 S 15 L 25 << 0 L 7 >> + 31 S 16 L 0 S 17 L 1 S 18 L 2 S 19 L 3 S 20 L 4 S 21 L 5 S 22 L 6 S 23 L 7 S 24 L 8 S 25 L 9 S 26 L 10 S 27 L 11 S 28 L 12 S 29 L 13 S 30 L 14 S 31 L 15 S 0 L 16 S 1 L 17 S 2 L 18 S 3 L 19 S 4 L 20 S 5 L 21 S 6 L 22 S 7 L 23 S 8 L 24 S 9 L 25 S 10 L 26 S 11 L 27 S 12 L 28 S 13 L 29 S 14 L 30 S 15 L 31 S 26 L 0 S 23 L 1 S 29 L 2 S 25 L 3 S 16 L 4 S 27 L 5 S 22 L 6 S 24 L 7 S 28 L 8 S 18 L 9 S 20 L 10 S 21 L 11 S 30 L 12 S 31 L 13 S 19 L 14 S 17 L 15 S 0 L 2131456702 ^ 0 S 1 L 2131456702 ^ 1 S 2 L 2131456702 ^ 2 S 3 L 2131456702 ^ 3 S 4 L 2131456702 ^ 4 S 5 L 2131456702 ^ 5 S 6 L 2131456702 ^ 6 S 7 L 2131456702 ^ 7 S 8 L 2131456702 ^ 8 S 9 L 2131456702 ^ 9 S 10 L 2131456702 ^ 10 S 11 L 2131456702 ^ 11 S 12 L 2131456702 ^ 12 S 13 L 2131456702 ^ 13 S 14 L 2131456702 ^ 14 S 15 L 2131456702 ^ 15 S 0 L 13 << 1 L 19 >> + 16 S 1 L 13 << 2 L 19 >> + 17 S 2 L 13 << 3 L 19 >> + 18 S 3 L 13 << 4 L 19 >> + 19 S 4 L 13 << 5 L 19 >> + 20 S 5 L 13 << 6 L 19 >> + 21 S 6 L 13 << 7 L 19 >> + 22 S 7 L 13 << 8 L 19 >> + 23 S 8 L 13 << 9 L 19 >> + 24 S 9 L 13 << 10 L 19 >> + 25 S 10 L 13 << 11 L 19 >> + 26 S 11 L 13 << 12 L 19 >> + 27 S 12 L 13 << 13 L 19 >> + 28 S 13 L 13 << 14 L 19 >> + 29 S 14 L 13 << 15 L 19 >> + 30 S 15 L 13 << 0 L 19 >> + 31 S 16 L 0 S 17 L 1 S 18 L 2 S 19 L 3 S 20 L 4 S 21 L 5 S 22 L 6 S 23 L 7 S 24 L 8 S 25 L 9 S 26 L 10 S 27 L 11 S 28 L 12 S 29 L 13 S 30 L 14 S 31 L 15 S 0 L 3819789533 + 0 S 1 L 2726830983 + 1 S 2 L 3833169646 + 2 S 3 L 2626451223 + 3 S 4 L 235643248 + 4 S 5 L 2751391122 + 5 S 6 L 3250809718 + 6 S 7 L 3469357344 + 7 S 8 L 1840106532 + 8 S 9 L 2373383695 + 9 S 10 L 613411799 + 10 S 11 L 906499033 + 11 S 12 L 2400588461 + 12 S 13 L 180890709 + 13 S 14 L 3150076576 + 14 S 15 L 4158018775 + 15 S 0 L 16 S 1 L 17 S 2 L 18 S 3 L 19 S 4 L 20 S 5 L 21 S 6 L 22 S 7 L 23 S 8 L 24 S 9 L 25 S 10 L 26 S 11 L 27 S 12 L 28 S 13 L 29 S 14 L 30 S 15 L 31 S 29 L 0 S 21 L 1 S 17 L 2 S 23 L 3 S 22 L 4 S 28 L 5 S 24 L 6 S 27 L 7 S 25 L 8 S 18 L 9 S 30 L 10 S 31 L 11 S 16 L 12 S 26 L 13 S 20 L 14 S 19 L 15 S 0 L 1024365459 ^ 0 S 1 L 1024365459 ^ 1 S 2 L 1024365459 ^ 2 S 3 L 1024365459 ^ 3 S 4 L 1024365459 ^ 4 S 5 L 1024365459 ^ 5 S 6 L 1024365459 ^ 6 S 7 L 1024365459 ^ 7 S 8 L 1024365459 ^ 8 S 9 L 1024365459 ^ 9 S 10 L 1024365459 ^ 10 S 11 L 1024365459 ^ 11 S 12 L 1024365459 ^ 12 S 13 L 1024365459 ^ 13 S 14 L 1024365459 ^ 14 S 15 L 1024365459 ^ 15 S 0 L 10 << 1 L 22 >> + 16 S 1 L 10 << 2 L 22 >> + 17 S 2 L 10 << 3 L 22 >> + 18 S 3 L 10 << 4 L 22 >> + 19 S 4 L 10 << 5 L 22 >> + 20 S 5 L 10 << 6 L 22 >> + 21 S 6 L 10 << 7 L 22 >> + 22 S 7 L 10 << 8 L 22 >> + 23 S 8 L 10 << 9 L 22 >> + 24 S 9 L 10 << 10 L 22 >> + 25 S 10 L 10 << 11 L 22 >> + 26 S 11 L 10 << 12 L 22 >> + 27 S 12 L 10 << 13 L 22 >> + 28 S 13 L 10 << 14 L 22 >> + 29 S 14 L 10 << 15 L 22 >> + 30 S 15 L 10 << 0 L 22 >> + 31 S 16 L 0 S 17 L 1 S 18 L 2 S 19 L 3 S 20 L 4 S 21 L 5 S 22 L 6 S 23 L 7 S 24 L 8 S 25 L 9 S 26 L 10 S 27 L 11 S 28 L 12 S 29 L 13 S 30 L 14 S 31 L 15 S 0 L 1862387496 ^ 0 S 1 L 1862387496 ^ 1 S 2 L 1862387496 ^ 2 S 3 L 1862387496 ^ 3 S 4 L 1862387496 ^ 4 S 5 L 1862387496 ^ 5 S 6 L 1862387496 ^ 6 S 7 L 1862387496 ^ 7 S 8 L 1862387496 ^ 8 S 9 L 1862387496 ^ 9 S 10 L 1862387496 ^ 10 S 11 L 1862387496 ^ 11 S 12 L 1862387496 ^ 12 S 13 L 1862387496 ^ 13 S 14 L 1862387496 ^ 14 S 15 L 1862387496 ^ 15 S 0 L 4052043025 + 0 S 1 L 38454011 + 1 S 2 L 40603131 + 2 S 3 L 495554080 + 3 S 4 L 3145077491 + 4 S 5 L 4081303155 + 5 S 6 L 3564686869 + 6 S 7 L 3136057325 + 7 S 8 L 2748420511 + 8 S 9 L 4270471087 + 9 S 10 L 1703402725 + 10 S 11 L 2522476144 + 11 S 12 L 2073653954 + 12 S 13 L 1171899438 + 13 S 14 L 2462594363 + 14 S 15 L 411786872 + 15 S 0 L 16 S 1 L 17 S 2 L 18 S 3 L 19 S 4 L 20 S 5 L 21 S 6 L 22 S 7 L 23 S 8 L 24 S 9 L 25 S 10 L 26 S 11 L 27 S 12 L 28 S 13 L 29 S 14 L 30 S 15 L 31 S 19 L 0 S 25 L 1 S 21 L 2 S 16 L 3 S 24 L 4 S 30 L 5 S 26 L 6 S 22 L 7 S 17 L 8 S 27 L 9 S 29 L 10 S 20 L 11 S 28 L 12 S 23 L 13 S 18 L 14 S 31 L 15 S 0 L 163058214 + 0 S 1 L 2343756067 + 1 S 2 L 2302751200 + 2 S 3 L 1916020293 + 3 S 4 L 3242878946 + 4 S 5 L 2055158854 + 5 S 6 L 3631048001 + 6 S 7 L 259711940 + 7 S 8 L 1804165076 + 8 S 9 L 3650156993 + 9 S 10 L 1184074030 + 10 S 11 L 1143932508 + 11 S 12 L 3129173080 + 12 S 13 L 2296633226 + 13 S 14 L 720287629 + 14 S 15 L 2838659044 + 15 S 0 L 13 << 1 L 19 >> + 16 S 1 L 13 << 2 L 19 >> + 17 S 2 L 13 << 3 L 19 >> + 18 S 3 L 13 << 4 L 19 >> + 19 S 4 L 13 << 5 L 19 >> + 20 S 5 L 13 << 6 L 19 >> + 21 S 6 L 13 << 7 L 19 >> + 22 S 7 L 13 << 8 L 19 >> + 23 S 8 L 13 << 9 L 19 >> + 24 S 9 L 13 << 10 L 19 >> + 25 S 10 L 13 << 11 L 19 >> + 26 S 11 L 13 << 12 L 19 >> + 27 S 12 L 13 << 13 L 19 >> + 28 S 13 L 13 << 14 L 19 >> + 29 S 14 L 13 << 15 L 19 >> + 30 S 15 L 13 << 0 L 19 >> + 31 S 16 L 0 S 17 L 1 S 18 L 2 S 19 L 3 S 20 L 4 S 21 L 5 S 22 L 6 S 23 L 7 S 24 L 8 S 25 L 9 S 26 L 10 S 27 L 11 S 28 L 12 S 29 L 13 S 30 L 14 S 31 L 15 S 0 L 2215993860 + 0 S 1 L 303890254 + 1 S 2 L 993170000 + 2 S 3 L 2913349220 + 3 S 4 L 2845923749 + 4 S 5 L 2733180324 + 5 S 6 L 1441518799 + 6 S 7 L 498214075 + 7 S 8 L 1804352726 + 8 S 9 L 940022388 + 9 S 10 L 3000229639 + 10 S 11 L 1082427506 + 11 S 12 L 3843075092 + 12 S 13 L 2082252804 + 13 S 14 L 1480546821 + 14 S 15 L 3942361756 + 15 S 0 L 27 << 1 L 5 >> + 16 S 1 L 27 << 2 L 5 >> + 17 S 2 L 27 << 3 L 5 >> + 18 S 3 L 27 << 4 L 5 >> + 19 S 4 L 27 << 5 L 5 >> + 20 S 5 L 27 << 6 L 5 >> + 21 S 6 L 27 << 7 L 5 >> + 22 S 7 L 27 << 8 L 5 >> + 23 S 8 L 27 << 9 L 5 >> + 24 S 9 L 27 << 10 L 5 >> + 25 S 10 L 27 << 11 L 5 >> + 26 S 11 L 27 << 12 L 5 >> + 27 S 12 L 27 << 13 L 5 >> + 28 S 13 L 27 << 14 L 5 >> + 29 S 14 L 27 << 15 L 5 >> + 30 S 15 L 27 << 0 L 5 >> + 31 S 16 L 0 S 17 L 1 S 18 L 2 S 19 L 3 S 20 L 4 S 21 L 5 S 22 L 6 S 23 L 7 S 24 L 8 S 25 L 9 S 26 L 10 S 27 L 11 S 28 L 12 S 29 L 13 S 30 L 14 S 31 L 15 S 0 L 1448893203 + 0 S 1 L 2487020138 + 1 S 2 L 2471808214 + 2 S 3 L 2310018932 + 3 S 4 L 888546786 + 4 S 5 L 3146236124 + 5 S 6 L 3387176834 + 6 S 7 L 2217875855 + 7 S 8 L 3286917575 + 8 S 9 L 945157930 + 9 S 10 L 2620516421 + 10 S 11 L 1110675164 + 11 S 12 L 37283074 + 12 S 13 L 1471865203 + 13 S 14 L 3008348481 + 14 S 15 L 2331454911 + 15 S 0 L 16 S 1 L 17 S 2 L 18 S 3 L 19 S 4 L 20 S 5 L 21 S 6 L 22 S 7 L 23 S 8 L 24 S 9 L 25 S 10 L 26 S 11 L 27 S 12 L 28 S 13 L 29 S 14 L 30 S 15 L 31 S 29 L 0 S 20 L 1 S 17 L 2 S 30 L 3 S 27 L 4 S 19 L 5 S 31 L 6 S 22 L 7 S 16 L 8 S 18 L 9 S 28 L 10 S 26 L 11 S 25 L 12 S 23 L 13 S 21 L 14 S 24 L 15 S 0 L 10 << 1 L 22 >> + 16 S 1 L 10 << 2 L 22 >> + 17 S 2 L 10 << 3 L 22 >> + 18 S 3 L 10 << 4 L 22 >> + 19 S 4 L 10 << 5 L 22 >> + 20 S 5 L 10 << 6 L 22 >> + 21 S 6 L 10 << 7 L 22 >> + 22 S 7 L 10 << 8 L 22 >> + 23 S 8 L 10 << 9 L 22 >> + 24 S 9 L 10 << 10 L 22 >> + 25 S 10 L 10 << 11 L 22 >> + 26 S 11 L 10 << 12 L 22 >> + 27 S 12 L 10 << 13 L 22 >> + 28 S 13 L 10 << 14 L 22 >> + 29 S 14 L 10 << 15 L 22 >> + 30 S 15 L 10 << 0 L 22 >> + 31 S 16 L 0 S 17 L 1 S 18 L 2 S 19 L 3 S 20 L 4 S 21 L 5 S 22 L 6 S 23 L 7 S 24 L 8 S 25 L 9 S 26 L 10 S 27 L 11 S 28 L 12 S 29 L 13 S 30 L 14 S 31 L 15 S 0 L 20 << 1 L 12 >> + 16 S 1 L 20 << 2 L 12 >> + 17 S 2 L 20 << 3 L 12 >> + 18 S 3 L 20 << 4 L 12 >> + 19 S 4 L 20 << 5 L 12 >> + 20 S 5 L 20 << 6 L 12 >> + 21 S 6 L 20 << 7 L 12 >> + 22 S 7 L 20 << 8 L 12 >> + 23 S 8 L 20 << 9 L 12 >> + 24 S 9 L 20 << 10 L 12 >> + 25 S 10 L 20 << 11 L 12 >> + 26 S 11 L 20 << 12 L 12 >> + 27 S 12 L 20 << 13 L 12 >> + 28 S 13 L 20 << 14 L 12 >> + 29 S 14 L 20 << 15 L 12 >> + 30 S 15 L 20 << 0 L 12 >> + 31 S 16 L 0 S 17 L 1 S 18 L 2 S 19 L 3 S 20 L 4 S 21 L 5 S 22 L 6 S 23 L 7 S 24 L 8 S 25 L 9 S 26 L 10 S 27 L 11 S 28 L 12 S 29 L 13 S 30 L 14 S 31 L 15 S 0 L 245308283 + 0 S 1 L 2899142818 + 1 S 2 L 1520962167 + 2 S 3 L 3144317372 + 3 S 4 L 1221756955 + 4 S 5 L 3230459338 + 5 S 6 L 2395265821 + 6 S 7 L 1230408279 + 7 S 8 L 1033071431 + 8 S 9 L 1702641704 + 9 S 10 L 1883319382 + 10 S 11 L 3330845249 + 11 S 12 L 2082486757 + 12 S 13 L 1622732329 + 13 S 14 L 1077396446 + 14 S 15 L 1475388712 + 15 S 0 L 4220542219 ^ 0 S 1 L 4220542219 ^ 1 S 2 L 4220542219 ^ 2 S 3 L 4220542219 ^ 3 S 4 L 4220542219 ^ 4 S 5 L 4220542219 ^ 5 S 6 L 4220542219 ^ 6 S 7 L 4220542219 ^ 7 S 8 L 4220542219 ^ 8 S 9 L 4220542219 ^ 9 S 10 L 4220542219 ^ 10 S 11 L 4220542219 ^ 11 S 12 L 4220542219 ^ 12 S 13 L 4220542219 ^ 13 S 14 L 4220542219 ^ 14 S 15 L 4220542219 ^ 15 S 0 L 3785363846 + 0 S 1 L 1070554775 + 1 S 2 L 3030540013 + 2 S 3 L 1247466211 + 3 S 4 L 1761532377 + 4 S 5 L 2940385122 + 5 S 6 L 3897617237 + 6 S 7 L 3136090717 + 7 S 8 L 2376440596 + 8 S 9 L 1573569045 + 9 S 10 L 3147795214 + 10 S 11 L 3175121930 + 11 S 12 L 3939021460 + 12 S 13 L 1946400697 + 13 S 14 L 3712117240 + 14 S 15 L 2892375100 + 15 S 0 L 627361171 + 0 S 1 L 1286554340 + 1 S 2 L 1759499404 + 2 S 3 L 3218548009 + 3 S 4 L 329977576 + 4 S 5 L 1078273203 + 5 S 6 L 165473379 + 6 S 7 L 1638077464 + 7 S 8 L 3503182658 + 8 S 9 L 3113363084 + 9 S 10 L 1534276288 + 10 S 11 L 3914878400 + 11 S 12 L 2021564840 + 12 S 13 L 1410012146 + 13 S 14 L 1012680343 + 14 S 15 L 645132541 + 15 S 0 L 26 << 1 L 6 >> + 16 S 1 L 26 << 2 L 6 >> + 17 S 2 L 26 << 3 L 6 >> + 18 S 3 L 26 << 4 L 6 >> + 19 S 4 L 26 << 5 L 6 >> + 20 S 5 L 26 << 6 L 6 >> + 21 S 6 L 26 << 7 L 6 >> + 22 S 7 L 26 << 8 L 6 >> + 23 S 8 L 26 << 9 L 6 >> + 24 S 9 L 26 << 10 L 6 >> + 25 S 10 L 26 << 11 L 6 >> + 26 S 11 L 26 << 12 L 6 >> + 27 S 12 L 26 << 13 L 6 >> + 28 S 13 L 26 << 14 L 6 >> + 29 S 14 L 26 << 15 L 6 >> + 30 S 15 L 26 << 0 L 6 >> + 31 S 16 L 0 S 17 L 1 S 18 L 2 S 19 L 3 S 20 L 4 S 21 L 5 S 22 L 6 S 23 L 7 S 24 L 8 S 25 L 9 S 26 L 10 S 27 L 11 S 28 L 12 S 29 L 13 S 30 L 14 S 31 L 15 S")
print(bytecode)
vm = StackVM()
vm.execute(bytecode)

for i in range(16):
    print(ctypes.c_uint32(vm.mem[i]).value,end=',')