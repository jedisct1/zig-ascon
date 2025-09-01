//! ASCON-CXOF128 implementation according to NIST SP 800-232
//! Provides a customizable extendable output function with 128-bit security

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;
const core = @import("core.zig");

/// ASCON-CXOF128 as specified in NIST SP 800-232
pub const AsconCxof128 = struct {
    const rate = core.Rate.HASH_XOF;
    const max_customization_length = 256; // 2048 bits

    state: core.AsconState,
    squeezing: bool,

    /// Initialize a new CXOF state
    pub fn init() AsconCxof128 {
        return AsconCxof128{
            .state = core.initState(core.IV.CXOF128, ""),
            .squeezing = false,
        };
    }

    /// Absorb data with customization into the CXOF state
    pub fn absorb(self: *AsconCxof128, data: []const u8, customization: []const u8) void {
        std.debug.assert(!self.squeezing);
        std.debug.assert(customization.len <= max_customization_length);

        // Process customization string first
        if (customization.len > 0) {
            // Encode customization length as 16-bit little-endian
            var len_bytes: [2]u8 = undefined;
            mem.writeInt(u16, &len_bytes, @as(u16, @intCast(customization.len * 8)), .little);

            // Process length bytes
            self.state.addBytes(len_bytes[0..2]);

            // Process customization in first block with padding if needed
            if (customization.len <= rate - 2) {
                var block = [_]u8{0} ** rate;
                @memcpy(block[2 .. 2 + customization.len], customization);
                block[2 + customization.len] = 0x80;
                self.state.addBytes(&block);
                self.state.permuteR(core.Rounds.B_HASH);
            } else {
                // Customization spans multiple blocks
                var temp_block = [_]u8{0} ** rate;
                @memcpy(temp_block[2..], customization[0 .. rate - 2]);
                self.state.addBytes(&temp_block);
                self.state.permuteR(core.Rounds.B_HASH);

                // Process remaining customization
                const offset = core.processFullBlocks(&self.state, customization[rate - 2 ..], rate, core.Rounds.B_HASH);
                core.processLastBlockWithPermutation(&self.state, customization[rate - 2 ..], offset, rate, core.Rounds.B_HASH);
            }
        } else {
            // Empty customization - just encode zero length with padding
            var block = [_]u8{0} ** rate;
            block[2] = 0x80; // Padding after 2-byte length
            self.state.addBytes(&block);
            self.state.permuteR(core.Rounds.B_HASH);
        }

        // Process input data
        const offset = core.processFullBlocks(&self.state, data, rate, core.Rounds.B_HASH);
        core.processLastBlockWithPermutation(&self.state, data, offset, rate, core.Rounds.A);

        self.squeezing = true;
    }

    /// Squeeze output from the CXOF state
    pub fn squeeze(self: *AsconCxof128, out: []u8) void {
        std.debug.assert(self.squeezing);
        core.squeezeBlocks(&self.state, out, rate, core.Rounds.B_HASH);
    }

    /// One-shot CXOF function with customization
    pub fn cxof(out: []u8, msg: []const u8, customization: []const u8) void {
        var x = init();
        x.absorb(msg, customization);
        x.squeeze(out);
    }
};

test "ASCON-CXOF128 basic test" {
    const msg = "Hello, ASCON CXOF!";
    const custom = "MyContext";
    var output1: [32]u8 = undefined;

    // One-shot CXOF
    AsconCxof128.cxof(&output1, msg, custom);

    // Manual absorb/squeeze
    var x = AsconCxof128.init();
    x.absorb(msg, custom);
    var output2: [32]u8 = undefined;
    x.squeeze(&output2);

    try testing.expectEqualSlices(u8, &output1, &output2);
}

test "ASCON-CXOF128 different customizations" {
    const msg = "Test message";
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;
    var out3: [32]u8 = undefined;

    AsconCxof128.cxof(&out1, msg, "");
    AsconCxof128.cxof(&out2, msg, "Context1");
    AsconCxof128.cxof(&out3, msg, "Context2");

    // Different customizations should produce different outputs
    try testing.expect(!mem.eql(u8, &out1, &out2));
    try testing.expect(!mem.eql(u8, &out1, &out3));
    try testing.expect(!mem.eql(u8, &out2, &out3));
}

test "ASCON-CXOF128 empty customization" {
    const msg = "Test";
    var output: [32]u8 = undefined;

    AsconCxof128.cxof(&output, msg, "");

    // Should produce valid output
    var output2: [32]u8 = undefined;
    AsconCxof128.cxof(&output2, msg, "");
    try testing.expectEqualSlices(u8, &output, &output2);
}

test "ASCON-CXOF128 long customization" {
    const msg = "Test";
    const long_custom = "A" ** 200; // 200 bytes customization
    var output: [32]u8 = undefined;

    AsconCxof128.cxof(&output, msg, long_custom);

    // Should work with long customization
    var output2: [32]u8 = undefined;
    AsconCxof128.cxof(&output2, msg, long_custom);
    try testing.expectEqualSlices(u8, &output, &output2);
}
