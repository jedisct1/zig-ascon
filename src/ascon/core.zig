//! Core ASCON functionality wrapper for NIST SP 800-232
//! This module provides the basic building blocks for all ASCON algorithms

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;

/// ASCON state using little-endian representation as per NIST SP 800-232
pub const AsconState = crypto.core.Ascon(.little);

/// Common round constants
pub const Rounds = struct {
    pub const A = 12; // Full permutation rounds
    pub const B_AEAD = 8; // Reduced rounds for AEAD
    pub const B_HASH = 12; // Reduced rounds for Hash/XOF
};

/// Initial values for each algorithm from NIST SP 800-232
pub const IV = struct {
    pub const AEAD128: u64 = 0x00001000808c0001;
    pub const HASH256: u64 = 0x0000080100cc0002;
    pub const XOF128: u64 = 0x0000080000cc0003;
    pub const CXOF128: u64 = 0x0000080000cc0004;
};

/// Rate constants for each algorithm (in bytes)
pub const Rate = struct {
    pub const AEAD128 = 16; // 128 bits
    pub const HASH_XOF = 8; // 64 bits
};

/// Initialize state with IV and optional additional data
pub fn initState(iv: u64, additional: []const u8) AsconState {
    var initial = [_]u8{0} ** AsconState.block_bytes;
    mem.writeInt(u64, initial[0..8], iv, .little);
    if (additional.len > 0) {
        @memcpy(initial[8..][0..additional.len], additional);
    }
    return AsconState.init(initial);
}

/// Process full blocks of data with permutation
pub fn processFullBlocks(state: *AsconState, data: []const u8, rate: usize, comptime rounds: u4) usize {
    var offset: usize = 0;
    while (offset + rate <= data.len) : (offset += rate) {
        state.addBytes(data[offset..][0..rate]);
        state.permuteR(rounds);
    }
    return offset;
}

/// Process last block with padding
pub fn processLastBlock(state: *AsconState, data: []const u8, offset: usize, rate: usize) void {
    var last_block = [_]u8{0} ** 16; // Max rate size
    const remaining = data.len - offset;
    if (remaining > 0) {
        @memcpy(last_block[0..remaining], data[offset..]);
    }
    last_block[remaining] = 0x80;
    state.addBytes(last_block[0..rate]);
}

/// Process last block with padding and apply final permutation
pub fn processLastBlockWithPermutation(state: *AsconState, data: []const u8, offset: usize, rate: usize, comptime rounds: u4) void {
    processLastBlock(state, data, offset, rate);
    state.permuteR(rounds);
}

/// Squeeze output from state with permutation between blocks
pub fn squeezeBlocks(state: *AsconState, out: []u8, rate: usize, comptime rounds: u4) void {
    var offset: usize = 0;
    while (offset < out.len) {
        var state_bytes = [_]u8{0} ** AsconState.block_bytes;
        state.extractBytes(&state_bytes);

        const to_copy = @min(rate, out.len - offset);
        @memcpy(out[offset..][0..to_copy], state_bytes[0..to_copy]);
        offset += to_copy;

        if (offset < out.len) {
            state.permuteR(rounds);
        }
    }
}

/// Padding function as specified in NIST SP 800-232
/// Appends 0x80 followed by zeros to make the data a multiple of rate bytes
pub fn pad(allocator: mem.Allocator, data: []const u8, rate: usize) ![]u8 {
    const padded_len = ((data.len / rate) + 1) * rate;
    var padded = try allocator.alloc(u8, padded_len);
    @memcpy(padded[0..data.len], data);
    padded[data.len] = 0x80;
    if (data.len + 1 < padded_len) {
        @memset(padded[data.len + 1 ..], 0);
    }
    return padded;
}

/// Padding function that operates in-place on a buffer
/// Returns the padded length
pub fn padInPlace(buffer: []u8, data_len: usize, rate: usize) usize {
    std.debug.assert(buffer.len >= ((data_len / rate) + 1) * rate);
    buffer[data_len] = 0x80;
    const padded_len = ((data_len / rate) + 1) * rate;
    if (data_len + 1 < padded_len) {
        @memset(buffer[data_len + 1 .. padded_len], 0);
    }
    return padded_len;
}

/// Helper to XOR bytes into state at a specific offset
pub fn xorBytesAt(state: *AsconState, data: []const u8, offset: usize) void {
    var temp = [_]u8{0} ** AsconState.block_bytes;
    state.extractBytes(&temp);
    for (data, 0..) |byte, i| {
        if (offset + i < temp.len) {
            temp[offset + i] ^= byte;
        }
    }
    state.setBytes(&temp);
}

/// Helper to extract bytes from state at a specific offset
pub fn extractBytesAt(state: *AsconState, out: []u8, offset: usize) void {
    var temp = [_]u8{0} ** AsconState.block_bytes;
    state.extractBytes(&temp);
    @memcpy(out, temp[offset..][0..out.len]);
}

test "padding" {
    const allocator = testing.allocator;

    // Test padding empty data
    {
        const data = "";
        const padded = try pad(allocator, data, 8);
        defer allocator.free(padded);
        try testing.expectEqual(@as(usize, 8), padded.len);
        try testing.expectEqual(@as(u8, 0x80), padded[0]);
        for (padded[1..]) |byte| {
            try testing.expectEqual(@as(u8, 0), byte);
        }
    }

    // Test padding with partial block
    {
        const data = "abc";
        const padded = try pad(allocator, data, 8);
        defer allocator.free(padded);
        try testing.expectEqual(@as(usize, 8), padded.len);
        try testing.expectEqualSlices(u8, "abc", padded[0..3]);
        try testing.expectEqual(@as(u8, 0x80), padded[3]);
        for (padded[4..]) |byte| {
            try testing.expectEqual(@as(u8, 0), byte);
        }
    }

    // Test padding with full block
    {
        const data = "abcdefgh";
        const padded = try pad(allocator, data, 8);
        defer allocator.free(padded);
        try testing.expectEqual(@as(usize, 16), padded.len);
        try testing.expectEqualSlices(u8, "abcdefgh", padded[0..8]);
        try testing.expectEqual(@as(u8, 0x80), padded[8]);
        for (padded[9..]) |byte| {
            try testing.expectEqual(@as(u8, 0), byte);
        }
    }
}

test "padInPlace" {
    // Test padding empty data
    {
        var buffer = [_]u8{0xFF} ** 16;
        const padded_len = padInPlace(&buffer, 0, 8);
        try testing.expectEqual(@as(usize, 8), padded_len);
        try testing.expectEqual(@as(u8, 0x80), buffer[0]);
        for (buffer[1..8]) |byte| {
            try testing.expectEqual(@as(u8, 0), byte);
        }
    }

    // Test padding with partial block
    {
        var buffer = [_]u8{0xFF} ** 16;
        buffer[0] = 'a';
        buffer[1] = 'b';
        buffer[2] = 'c';
        const padded_len = padInPlace(&buffer, 3, 8);
        try testing.expectEqual(@as(usize, 8), padded_len);
        try testing.expectEqual(@as(u8, 'a'), buffer[0]);
        try testing.expectEqual(@as(u8, 'b'), buffer[1]);
        try testing.expectEqual(@as(u8, 'c'), buffer[2]);
        try testing.expectEqual(@as(u8, 0x80), buffer[3]);
        for (buffer[4..8]) |byte| {
            try testing.expectEqual(@as(u8, 0), byte);
        }
    }
}
