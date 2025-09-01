# ASCON Cryptographic Algorithms for Zig

A complete implementation of the ASCON family of lightweight cryptographic algorithms as specified in [NIST SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/ipd), written in pure Zig.

## Features

This library implements all four ASCON algorithms standardized by NIST:

- **ASCON-AEAD128**: Authenticated encryption with associated data (128-bit security)
- **ASCON-HASH256**: Cryptographic hash function (256-bit output)
- **ASCON-XOF128**: Extendable output function (128-bit security)
- **ASCON-CXOF128**: Customizable extendable output function with domain separation

## Specification Compliance

This implementation strictly follows:
- [NIST SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/ipd): Ascon-based Lightweight Cryptography Standard
- Little-endian representation as mandated by NIST
- All specified initial values, round counts, and domain separation bits
