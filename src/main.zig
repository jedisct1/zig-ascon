const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AsconState = crypto.core.Ascon(.Big);
const AuthenticationError = crypto.errors.AuthenticationError;

const rate = 16;

const AeadState128a = struct {
    const Self = @This();

    p: AsconState,
    k1: u64,
    k2: u64,

    fn init(key: [16]u8, nonce: [16]u8) Self {
        const k1 = mem.readIntBig(u64, key[0..8]);
        const k2 = mem.readIntBig(u64, key[8..][0..8]);
        const n1 = mem.readIntBig(u64, nonce[0..8]);
        const n2 = mem.readIntBig(u64, nonce[8..][0..8]);
        const words: [5]u64 = .{ 0x80800c0800000000, k1, k2, n1, n2 };
        var p = AsconState.initFromWords(words);
        p.permute();
        p.st[3] ^= k1;
        p.st[4] ^= k2;
        return Self{ .k1 = k1, .k2 = k2, .p = p };
    }

    fn absorbAd(self: *Self, src: []const u8) void {
        if (src.len > 0) {
            var i: usize = 0;
            while (i + rate <= src.len) : (i += 16) {
                self.p.addBytes(src[i..][0..16]);
                self.p.permuteR(8);
            }
            var padded = [_]u8{0} ** 16;
            mem.copy(u8, &padded, src[i..]);
            padded[src.len - i] = 0x80;
            self.p.addBytes(&padded);
            self.p.permuteR(8);
        }
        self.p.st[4] ^= 0x01;
    }

    fn enc(self: *Self, dst: []u8, src: []const u8) void {
        assert(src.len == dst.len);
        var i: usize = 0;
        while (i + rate <= src.len) : (i += 16) {
            self.p.addBytes(src[i..][0..16]);
            self.p.extractBytes(dst[i..][0..16]);                        
            self.p.permuteR(8);
        }
        var padded = [_]u8{0} ** 16;
        mem.copy(u8, &padded, src[i..]);
        padded[i % 16] = 0x80;
        self.p.addBytes(&padded);
        self.p.extractBytes(dst[i..]);
    }

    fn dec(self: *Self, dst: []u8, src: []const u8) void {
        assert(dst.len == src.len);
        var i: usize = 0;
        while (i + rate <= dst.len) : (i += 16) {
            self.p.xorBytes(dst[i..][0..16], src[i..][0..16]);
            self.p.addBytes(dst[i..][0..16]);
            self.p.permuteR(8);
        }
        self.p.xorBytes(dst[i..], src[i..]);
        self.p.addBytes(dst[i..]);
        self.p.addByte(0x80, i % 16);
    }

    fn mac(self: *Self) [16]u8 {
        self.p.st[2] ^= self.k1;
        self.p.st[3] ^= self.k2;
        self.p.permute();
        self.p.st[3] ^= self.k1;
        self.p.st[4] ^= self.k2;

        var tag: [16]u8 = undefined;
        mem.writeIntBig(u64, tag[0..8], self.p.st[3]);
        mem.writeIntBig(u64, tag[8..][0..8], self.p.st[4]);
        return tag;
    }
};

pub const AsconAead128a = struct {
    pub const tag_length = 16;
    pub const nonce_length = 16;
    pub const key_length = 16;
    pub const block_length = 16;

    const State = AeadState128a;

    /// c: ciphertext: output buffer should be of size m.len
    /// tag: authentication tag: output MAC
    /// m: message
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
        assert(c.len == m.len);
        var st = State.init(key, npub);
        st.absorbAd(ad);
        st.enc(c, m);
        mem.copy(u8, tag[0..], st.mac()[0..]);
    }

    /// m: message: output buffer should be of size c.len
    /// c: ciphertext
    /// tag: authentication tag
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
        assert(c.len == m.len);
        var st = State.init(key, npub);
        st.absorbAd(ad);
        st.dec(m, c);
        if (!crypto.utils.timingSafeEql([16]u8, st.mac(), tag)) {
            @memset(m.ptr, undefined, m.len);
            return error.AuthenticationFailed;
        }
    }
};
