//! ASCON-AEAD128 implementation according to NIST SP 800-232
//! Provides authenticated encryption with associated data

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;
const core = @import("core.zig");

/// ASCON-AEAD128 as specified in NIST SP 800-232
pub const AsconAead128 = struct {
    pub const key_length = 16;
    pub const nonce_length = 16;
    pub const tag_length = 16;

    const rate = core.Rate.AEAD128;

    /// Encrypt plaintext with associated data
    pub fn encrypt(
        c: []u8,
        tag: *[tag_length]u8,
        m: []const u8,
        ad: []const u8,
        npub: [nonce_length]u8,
        key: [key_length]u8,
    ) void {
        std.debug.assert(c.len == m.len);

        var state = initializeState(key, npub);
        processAssociatedData(&state, ad);
        encryptData(&state, c, m);
        generateTag(&state, tag, key);
    }

    /// Decrypt ciphertext with associated data
    pub fn decrypt(
        m: []u8,
        c: []const u8,
        tag: [tag_length]u8,
        ad: []const u8,
        npub: [nonce_length]u8,
        key: [key_length]u8,
    ) !void {
        std.debug.assert(m.len == c.len);

        var state = initializeState(key, npub);
        processAssociatedData(&state, ad);
        decryptData(&state, m, c);

        var computed_tag: [tag_length]u8 = undefined;
        generateTag(&state, &computed_tag, key);

        // Timing-safe comparison
        if (!crypto.timing_safe.eql([tag_length]u8, computed_tag, tag)) {
            crypto.secureZero(u8, m);
            return error.AuthenticationFailed;
        }
    }

    // Internal functions

    fn initializeState(key: [key_length]u8, nonce: [nonce_length]u8) core.AsconState {
        // Initialize with IV || K || N
        var initial = [_]u8{0} ** core.AsconState.block_bytes;
        mem.writeInt(u64, initial[0..8], core.IV.AEAD128, .little);
        @memcpy(initial[8..24], &key);
        @memcpy(initial[24..40], &nonce);

        var state = core.AsconState.init(initial);

        // Apply permutation p^a
        state.permuteR(core.Rounds.A);

        // XOR key at the end
        var key_bytes = [_]u8{0} ** core.AsconState.block_bytes;
        @memcpy(key_bytes[24..40], &key);
        state.addBytes(&key_bytes);

        return state;
    }

    fn processAssociatedData(state: *core.AsconState, ad: []const u8) void {
        if (ad.len == 0) {
            // Domain separation for empty AD
            state.addByte(0x01, core.AsconState.block_bytes - 1);
            return;
        }

        // Process full blocks
        const offset = core.processFullBlocks(state, ad, rate, core.Rounds.B_AEAD);

        // Process last block with padding
        core.processLastBlockWithPermutation(state, ad, offset, rate, core.Rounds.B_AEAD);

        // Domain separation
        state.addByte(0x01, core.AsconState.block_bytes - 1);
    }

    fn encryptData(state: *core.AsconState, c: []u8, m: []const u8) void {
        // Process full blocks
        var i: usize = 0;
        while (i + rate <= m.len) : (i += rate) {
            state.addBytes(m[i..][0..rate]);
            state.extractBytes(c[i..][0..rate]);
            state.permuteR(core.Rounds.B_AEAD);
        }

        // Process last block with padding
        const remaining = m.len - i;
        if (remaining > 0) {
            var last_block = [_]u8{0} ** rate;
            @memcpy(last_block[0..remaining], m[i..]);
            last_block[remaining] = 0x80;

            state.addBytes(&last_block);
            state.extractBytes(c[i..][0..remaining]);
        } else {
            // Empty last block, just add padding
            state.addByte(0x80, 0);
        }
    }

    fn decryptData(state: *core.AsconState, m: []u8, c: []const u8) void {
        // Process full blocks
        var i: usize = 0;
        while (i + rate <= c.len) : (i += rate) {
            state.xorBytes(m[i..][0..rate], c[i..][0..rate]);
            state.setBytes(c[i..][0..rate]);
            state.permuteR(core.Rounds.B_AEAD);
        }

        // Process last block with padding
        const remaining = c.len - i;
        if (remaining > 0) {
            var state_bytes = [_]u8{0} ** core.AsconState.block_bytes;
            state.extractBytes(&state_bytes);

            // Decrypt remaining bytes
            for (0..remaining) |j| {
                m[i + j] = c[i + j] ^ state_bytes[j];
                state_bytes[j] = c[i + j];
            }
            state_bytes[remaining] ^= 0x80;

            state.setBytes(&state_bytes);
        } else {
            // Empty last block, just add padding
            state.addByte(0x80, 0);
        }
    }

    fn generateTag(state: *core.AsconState, tag: *[tag_length]u8, key: [key_length]u8) void {
        // XOR key
        var key_bytes = [_]u8{0} ** core.AsconState.block_bytes;
        @memcpy(key_bytes[rate .. rate + key_length], &key);
        state.addBytes(&key_bytes);

        // Apply permutation p^a
        state.permuteR(core.Rounds.A);

        // XOR key again and extract tag
        state.addBytes(key_bytes[24..]);
        var state_bytes = [_]u8{0} ** core.AsconState.block_bytes;
        state.extractBytes(&state_bytes);
        @memcpy(tag, state_bytes[24..40]);
    }
};

test "ASCON-AEAD128 basic encryption/decryption" {
    const key = [_]u8{0x00} ** 16;
    const nonce = [_]u8{0x00} ** 16;
    const plaintext = "Hello, ASCON!";
    const ad = "Additional data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    // Encrypt
    AsconAead128.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key);

    // Decrypt
    var decrypted: [plaintext.len]u8 = undefined;
    try AsconAead128.decrypt(&decrypted, &ciphertext, tag, ad, nonce, key);

    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "ASCON-AEAD128 authentication failure" {
    const key = [_]u8{0x00} ** 16;
    const nonce = [_]u8{0x00} ** 16;
    const plaintext = "Hello, ASCON!";
    const ad = "Additional data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    // Encrypt
    AsconAead128.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key);

    // Corrupt tag
    tag[0] ^= 0x01;

    // Decrypt should fail
    var decrypted: [plaintext.len]u8 = undefined;
    const result = AsconAead128.decrypt(&decrypted, &ciphertext, tag, ad, nonce, key);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "ASCON-AEAD128 empty plaintext" {
    const key = [_]u8{0x00} ** 16;
    const nonce = [_]u8{0x00} ** 16;
    const plaintext = "";
    const ad = "Additional data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    // Encrypt
    AsconAead128.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key);

    // Decrypt
    var decrypted: [plaintext.len]u8 = undefined;
    try AsconAead128.decrypt(&decrypted, &ciphertext, tag, ad, nonce, key);
}

test "ASCON-AEAD128 empty associated data" {
    const key = [_]u8{0x00} ** 16;
    const nonce = [_]u8{0x00} ** 16;
    const plaintext = "Hello, ASCON!";
    const ad = "";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    // Encrypt
    AsconAead128.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key);

    // Decrypt
    var decrypted: [plaintext.len]u8 = undefined;
    try AsconAead128.decrypt(&decrypted, &ciphertext, tag, ad, nonce, key);

    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}
