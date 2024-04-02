In this challenge, participants are asked to input 4 4-bytes passcode in the commmand line arguments.
There are 4 stages to solve this challenge:

## Stage1
In SEH handler, it will xor each byte of the passcode and get the 1-byte key to decrypt the shellcode.
To make this challenge run normally and trigger the exceptions in order, participants can just brute force the 1 bytes keys for 4 different shellcode.
So they will get this equation:
```
byte_key1 = passcode1[0] ^ passcode1[1] ^ passcode1[2] ^ passcode1[3]
byte_key2 = passcode2[0] ^ passcode2[1] ^ passcode2[2] ^ passcode2[3]
```
However, this is not very critical to decrypt the flag. 
If the shellcode is not decrypted correctly, there is no registered VEH handler.

In SEH handler, STATUS_GUARD_PAGE_VIOLATION will be triggered first. 
Because `0xcc` is the breakpoint instruction to trigger breakpoint exception in Windows, the 1-byte key is try to recover this byte.
And then, STATUS_BREAKPOINTS is expected to be triggered in the first and the second shellcode. 

STATUS_ILLEGAL_INSTRUCTION is the last exception to be triggered.
At this moment, if VEH handler is registered, it will handle the exception.
Otherwise, SEH handler will handle it and then exit the process. 

## Stage2
In VEH handler, there are 4 different shellcode will be decrypyted and then triggered.
Each shellcode has a corresponding exception to be triggered. 
There are some checksum comparisons for all 4 passcodes in each exception handling.
The equation looks like this:
```
checksum1 = (( ((passcode1 >> 24) & 0xff) | ((passcode1 >> 8) & 0xff00) | ((passcode1 << 16) & 0xffff0000) ) ^ passcode2) & 0xffffffff
checksum2 = (( ((passcode2 >> 24) & 0xff) | ((passcode2 >> 8) & 0xff00) | ((passcode2 << 16) & 0xffff0000) ) ^ passcode1) & 0xffffffff
checksum3 = (( ((passcode3 >> 24) & 0xff) | ((passcode3 >> 8) & 0xff00) | ((passcode3 << 16) & 0xffff0000) ) ^ passcode4) & 0xffffffff
checksum4 = (( ((passcode4 >> 24) & 0xff) | ((passcode4 >> 8) & 0xff00) | ((passcode4 << 16) & 0xffff0000) ) ^ passcode3) & 0xffffffff
```

In this case, it is not likely to brute force and find the answer in the limited time. 
In addition, if the checksum didn't matched, it will not jump to next shellcode. 

## Stage3
After Stage2 is finished, there is no exception handling before the gadget chain.
In this gadget chain, it will execute another checksum comparison like this: 
```
(passcode2 & 0xff) ^ 'A' == 0x99 
(passcode2 & 0xff) ^ '2' == 0x4f 
passcode1 ^ passcode2 == b"ACSC"
passcode3 ^ passcode4 == b"2024"
```

Each passcode can be split to four parts: a1 | a2 | a3 | a4
With the previous condition, you will have: C1 = a1^b3 | a2^b4 |  a3^b2 | a4^b1 --- (1)
In this stage, you have: K1 = a1^b1 | a2^b2 |  a3^b3 | a4^b4 --- (2)
Base on (1) and (2), you will get the values b1^b3, b4^b2, b2^b3, b1^b4
So, you only need to brute force any one-byte variable in the set {a1, a2, a3, a4, b1, b2, b3, b4}.
Because there are two sets of passcodes: {passcode1, passcode2}, {passcode3, passcode4}
You also have the answer of the last byte of passcode2 and passcode4.
In the end, you can recover the passcodes with these conditions.

Actually, `ACSC2024` is the title of the MessageBox.
If the check is failed, then the format of the MessageBox will turn from OK to Error.

## Stage4
If everything goes well, in the end, it will run the rc4 decryption to decrypt the flag and output the flag in the MessageBox.
