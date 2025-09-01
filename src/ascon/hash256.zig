//! ASCON-HASH256 implementation according to NIST SP 800-232
//! Provides a 256-bit cryptographic hash function

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;
const core = @import("core.zig");

/// ASCON-HASH256 as specified in NIST SP 800-232
pub const AsconHash256 = struct {
    pub const digest_length = 32; // 256 bits
    pub const block_length = core.Rate.HASH_XOF; // 8 bytes

    const rate = core.Rate.HASH_XOF;

    state: core.AsconState,
    buf: [block_length]u8,
    buf_len: usize,

    /// Initialize a new hash state
    pub fn init() AsconHash256 {
        return AsconHash256{
            .state = core.initState(core.IV.HASH256, ""),
            .buf = undefined,
            .buf_len = 0,
        };
    }

    /// Add data to the hash state
    pub fn update(self: *AsconHash256, data: []const u8) void {
        var remaining = data;

        // Process any buffered data first
        if (self.buf_len > 0) {
            const to_copy = @min(rate - self.buf_len, remaining.len);
            @memcpy(self.buf[self.buf_len..][0..to_copy], remaining[0..to_copy]);
            self.buf_len += to_copy;
            remaining = remaining[to_copy..];

            if (self.buf_len == rate) {
                self.state.addBytes(&self.buf);
                self.state.permuteR(core.Rounds.B_HASH);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        const offset = core.processFullBlocks(&self.state, remaining, rate, core.Rounds.B_HASH);
        remaining = remaining[offset..];

        // Buffer any remaining data
        if (remaining.len > 0) {
            @memcpy(self.buf[0..remaining.len], remaining);
            self.buf_len = remaining.len;
        }
    }

    /// Finalize the hash and output the digest
    pub fn final(self: *AsconHash256, out: *[digest_length]u8) void {
        // Apply padding to buffered data
        self.buf[self.buf_len] = 0x80;
        if (self.buf_len + 1 < rate) {
            @memset(self.buf[self.buf_len + 1 .. rate], 0);
        }

        // Process final block
        self.state.addBytes(self.buf[0..rate]);

        // Apply final permutation
        self.state.permuteR(core.Rounds.A);

        // Squeeze output
        core.squeezeBlocks(&self.state, out, rate, core.Rounds.B_HASH);
    }

    /// One-shot hash function
    pub fn hash(out: *[digest_length]u8, msg: []const u8) void {
        var h = init();
        h.update(msg);
        h.final(out);
    }
};

test "ASCON-HASH256 basic test" {
    const msg = "Hello, ASCON Hash!";
    var digest: [32]u8 = undefined;

    // One-shot hash
    AsconHash256.hash(&digest, msg);

    // Incremental hash
    var h = AsconHash256.init();
    h.update(msg[0..6]);
    h.update(msg[6..]);
    var digest2: [32]u8 = undefined;
    h.final(&digest2);

    try testing.expectEqualSlices(u8, &digest, &digest2);
}

test "ASCON-HASH256 empty message" {
    var digest: [32]u8 = undefined;
    AsconHash256.hash(&digest, "");

    // Empty message should still produce a valid hash
    var digest2: [32]u8 = undefined;
    AsconHash256.hash(&digest2, "");
    try testing.expectEqualSlices(u8, &digest, &digest2);
}

test "ASCON-HASH256 incremental update" {
    var h = AsconHash256.init();

    // Test multiple small updates
    h.update("a");
    h.update("b");
    h.update("c");
    h.update("d");
    h.update("e");

    var digest1: [32]u8 = undefined;
    h.final(&digest1);

    // Compare with single update
    var digest2: [32]u8 = undefined;
    AsconHash256.hash(&digest2, "abcde");

    try testing.expectEqualSlices(u8, &digest1, &digest2);
}
