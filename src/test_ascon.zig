//! Comprehensive test suite for ASCON implementations

const std = @import("std");
const testing = std.testing;
const aead128 = @import("ascon/aead128.zig");
const hash256 = @import("ascon/hash256.zig");
const xof128 = @import("ascon/xof128.zig");
const cxof128 = @import("ascon/cxof128.zig");

const AsconAead128 = aead128.AsconAead128;
const AsconHash256 = hash256.AsconHash256;
const AsconXof128 = xof128.AsconXof128;
const AsconCxof128 = cxof128.AsconCxof128;

test "All ASCON tests" {
    testing.refAllDecls(@This());
}

test "ASCON-AEAD128 round trip" {
    const key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 16;
    const plaintext = "The quick brown fox jumps over the lazy dog.";
    const ad = "Associated data for authentication";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    // Encrypt
    AsconAead128.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key);

    // Decrypt
    var decrypted: [plaintext.len]u8 = undefined;
    try AsconAead128.decrypt(&decrypted, &ciphertext, tag, ad, nonce, key);

    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "ASCON-HASH256 deterministic" {
    const msg1 = "Test message for hashing";
    const msg2 = "Different message";

    var hash1a: [32]u8 = undefined;
    var hash1b: [32]u8 = undefined;
    var hash2: [32]u8 = undefined;

    AsconHash256.hash(&hash1a, msg1);
    AsconHash256.hash(&hash1b, msg1);
    AsconHash256.hash(&hash2, msg2);

    // Same input should produce same hash
    try testing.expectEqualSlices(u8, &hash1a, &hash1b);

    // Different inputs should produce different hashes
    try testing.expect(!std.mem.eql(u8, &hash1a, &hash2));
}

test "ASCON-XOF128 extensible output" {
    const msg = "XOF test message";

    // Generate outputs of different lengths
    var out16: [16]u8 = undefined;
    var out32: [32]u8 = undefined;
    var out64: [64]u8 = undefined;

    AsconXof128.xof(&out16, msg);
    AsconXof128.xof(&out32, msg);
    AsconXof128.xof(&out64, msg);

    // Outputs should be consistent (prefix property)
    try testing.expectEqualSlices(u8, &out16, out32[0..16]);
    try testing.expectEqualSlices(u8, out32[0..32], out64[0..32]);
}

test "ASCON-CXOF128 customization" {
    const msg = "CXOF test message";
    const custom1 = "Domain1";
    const custom2 = "Domain2";

    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;
    var out3: [32]u8 = undefined;

    AsconCxof128.cxof(&out1, msg, "");
    AsconCxof128.cxof(&out2, msg, custom1);
    AsconCxof128.cxof(&out3, msg, custom2);

    // Different customizations should produce different outputs
    try testing.expect(!std.mem.eql(u8, &out1, &out2));
    try testing.expect(!std.mem.eql(u8, &out1, &out3));
    try testing.expect(!std.mem.eql(u8, &out2, &out3));
}

test "ASCON-AEAD128 wrong tag fails" {
    const key = [_]u8{0x03} ** 16;
    const nonce = [_]u8{0x04} ** 16;
    const plaintext = "Secret message";
    const ad = "Public data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    // Encrypt
    AsconAead128.encrypt(&ciphertext, &tag, plaintext, ad, nonce, key);

    // Corrupt the tag
    tag[0] ^= 0x01;

    // Decrypt should fail
    var decrypted: [plaintext.len]u8 = undefined;
    const result = AsconAead128.decrypt(&decrypted, &ciphertext, tag, ad, nonce, key);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "ASCON-HASH256 large input" {
    // Test with a large input
    var large_input: [10000]u8 = undefined;
    for (&large_input, 0..) |*byte, i| {
        byte.* = @as(u8, @intCast(i % 256));
    }

    var hash1: [32]u8 = undefined;
    var hash2: [32]u8 = undefined;

    // Hash in one go
    AsconHash256.hash(&hash1, &large_input);

    // Hash incrementally
    var h = AsconHash256.init();
    var offset: usize = 0;
    while (offset < large_input.len) : (offset += 1000) {
        const end = @min(offset + 1000, large_input.len);
        h.update(large_input[offset..end]);
    }
    h.final(&hash2);

    try testing.expectEqualSlices(u8, &hash1, &hash2);
}

test "ASCON-XOF128 incremental squeeze" {
    const msg = "Test for incremental squeezing";

    var x = AsconXof128.init();
    x.absorb(msg);

    // Squeeze in multiple parts
    var part1: [8]u8 = undefined;
    var part2: [8]u8 = undefined;
    var part3: [16]u8 = undefined;

    x.squeeze(&part1);
    x.squeeze(&part2);
    x.squeeze(&part3);

    // Compare with single squeeze
    var full: [32]u8 = undefined;
    AsconXof128.xof(&full, msg);

    try testing.expectEqualSlices(u8, &part1, full[0..8]);
    try testing.expectEqualSlices(u8, &part2, full[8..16]);
    try testing.expectEqualSlices(u8, &part3, full[16..32]);
}

test "ASCON cross-algorithm consistency" {
    // Test that different algorithms with same security level
    // produce different outputs for same input
    const input = "Common input for all algorithms";

    var hash_out: [32]u8 = undefined;
    var xof_out: [32]u8 = undefined;
    var cxof_out: [32]u8 = undefined;

    AsconHash256.hash(&hash_out, input);
    AsconXof128.xof(&xof_out, input);
    AsconCxof128.cxof(&cxof_out, input, "");

    // All should produce different outputs
    try testing.expect(!std.mem.eql(u8, &hash_out, &xof_out));
    try testing.expect(!std.mem.eql(u8, &hash_out, &cxof_out));
    try testing.expect(!std.mem.eql(u8, &xof_out, &cxof_out));
}
