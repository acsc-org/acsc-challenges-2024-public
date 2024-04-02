# strongest OAEP (25 solves)

### Summary: RSA-OAEP with broken mask generation function and 4-bit PRNG

The flag was encrypted with RSA-OAEP twice, but the mask generation function is broken and the PRNG's entropy is 4 bits. Therefore, most random elements are predictable in this cipher scheme, which is virtually the same as textbook RSA. You can solve this problem using the Franklin-Reiter Related Message Attack with a small amount of brute force. The public exponent is relatively large, so you need to use the Half-GCD algorithm to solve this problem efficiently.
