# Ascon128a AEAD for Zig

Ascon is the winner of the NIST lightweight crypto competition, and is being standardized by NIST.

Does it make sense to use it on desktop/server-class CPUs? It does. When running WebAssembly.

On WebAssembly, it is significantly faster than ChaChaPoly, and doesn't have any of the side channels issues that AES-based ciphers commonly have.

Plus, it's small. And blessed by NIST.