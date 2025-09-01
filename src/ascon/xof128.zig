//! ASCON-XOF128 implementation according to NIST SP 800-232
//! Provides an extendable output function with 128-bit security

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;
const core = @import("core.zig");

/// ASCON-XOF128 as specified in NIST SP 800-232
pub const AsconXof128 = struct {
    const rate = core.Rate.HASH_XOF;

    state: core.AsconState,
    squeezing: bool,
    squeeze_buffer: [rate]u8,
    squeeze_offset: usize,

    /// Initialize a new XOF state
    pub fn init() AsconXof128 {
        return AsconXof128{
            .state = core.initState(core.IV.XOF128, ""),
            .squeezing = false,
            .squeeze_buffer = undefined,
            .squeeze_offset = rate,
        };
    }

    /// Absorb data into the XOF state
    pub fn absorb(self: *AsconXof128, data: []const u8) void {
        std.debug.assert(!self.squeezing);

        // Process full blocks
        const offset = core.processFullBlocks(&self.state, data, rate, core.Rounds.B_HASH);

        // Process last block with padding and final permutation
        core.processLastBlockWithPermutation(&self.state, data, offset, rate, core.Rounds.A);

        self.squeezing = true;
    }

    /// Squeeze output from the XOF state
    pub fn squeeze(self: *AsconXof128, out: []u8) void {
        std.debug.assert(self.squeezing);

        var out_offset: usize = 0;
        var needed = out.len;

        while (needed > 0) {
            // If we need to extract more data
            if (self.squeeze_offset >= rate) {
                // Extract new block
                var state_bytes = [_]u8{0} ** core.AsconState.block_bytes;
                self.state.extractBytes(&state_bytes);
                @memcpy(&self.squeeze_buffer, state_bytes[0..rate]);
                self.squeeze_offset = 0;

                // Apply permutation for next block
                self.state.permuteR(core.Rounds.B_HASH);
            }

            // Copy from buffer
            const available = rate - self.squeeze_offset;
            const to_copy = @min(available, needed);
            @memcpy(out[out_offset..][0..to_copy], self.squeeze_buffer[self.squeeze_offset..][0..to_copy]);

            self.squeeze_offset += to_copy;
            out_offset += to_copy;
            needed -= to_copy;
        }
    }

    /// One-shot XOF function
    pub fn xof(out: []u8, msg: []const u8) void {
        var x = init();
        x.absorb(msg);
        x.squeeze(out);
    }
};

test "ASCON-XOF128 basic test" {
    const msg = "Hello, ASCON XOF!";
    var output1: [32]u8 = undefined;

    // One-shot XOF
    AsconXof128.xof(&output1, msg);

    // Manual absorb/squeeze
    var x = AsconXof128.init();
    x.absorb(msg);
    var output2: [32]u8 = undefined;
    x.squeeze(&output2);

    try testing.expectEqualSlices(u8, &output1, &output2);
}

test "ASCON-XOF128 variable length output" {
    const msg = "Test message";

    // Different output lengths
    var out16: [16]u8 = undefined;
    var out32: [32]u8 = undefined;
    var out64: [64]u8 = undefined;

    AsconXof128.xof(&out16, msg);
    AsconXof128.xof(&out32, msg);
    AsconXof128.xof(&out64, msg);

    // First 16 bytes should match
    try testing.expectEqualSlices(u8, &out16, out32[0..16]);
    try testing.expectEqualSlices(u8, &out16, out64[0..16]);

    // First 32 bytes should match
    try testing.expectEqualSlices(u8, &out32, out64[0..32]);
}

test "ASCON-XOF128 empty message" {
    var output: [32]u8 = undefined;
    AsconXof128.xof(&output, "");

    // Should produce valid output
    var output2: [32]u8 = undefined;
    AsconXof128.xof(&output2, "");
    try testing.expectEqualSlices(u8, &output, &output2);
}

test "ASCON-XOF128 incremental squeeze" {
    const msg = "Incremental test";

    var x = AsconXof128.init();
    x.absorb(msg);

    // Squeeze in parts
    var part1: [10]u8 = undefined;
    var part2: [10]u8 = undefined;
    var part3: [12]u8 = undefined;
    x.squeeze(&part1);
    x.squeeze(&part2);
    x.squeeze(&part3);

    // Compare with single squeeze
    var full: [32]u8 = undefined;
    AsconXof128.xof(&full, msg);

    try testing.expectEqualSlices(u8, &part1, full[0..10]);
    try testing.expectEqualSlices(u8, &part2, full[10..20]);
    try testing.expectEqualSlices(u8, &part3, full[20..32]);
}
