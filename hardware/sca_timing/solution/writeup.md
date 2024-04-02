- Provided File: An ELF Linux binary prompting the user for a PIN. The executable is designed to check the PIN from left to right, taking approximately 5ms for each correct digit and less than 0.1ms for an incorrect digit, exiting immediately. Participants should exploit this timing discrepancy to uncover the flag.

- solution: The ctf player can find the flag by performing a side channel timing attack. the 'time' shell command can be used to find the execution time. A shell script can be used to automate the process
