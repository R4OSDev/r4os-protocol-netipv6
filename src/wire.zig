//! Bounded IPv6 host parsing/reassembly. No addresses/routes or NIC owner here.
const std = @import("std");
const cursor = @import("r4os").binary_cursor;
pub const Address = [16]u8;
pub const capacity = 1504;
pub const Error = error{ Invalid, Discard, Unsupported, Capacity, Pending, Overlap, ParameterProblem };
pub const Reject = struct { code: u8 = 0, pointer: u32 = 0, multicast_exception: bool = false };
pub const Packet = struct {
    source: Address = .{0} ** 16,
    destination: Address = .{0} ** 16,
    next: u8 = 59,
    hop: u8 = 0,
    length: usize = 0,
    fragmented: bool = false,
    payload: [capacity]u8 = .{0} ** capacity,
};
const Fragment = struct {
    active: bool = false,
    rejected: bool = false,
    interface: u32 = 0,
    generation: u64 = 0,
    clock: u32 = 0,
    source: Address = .{0} ** 16,
    destination: Address = .{0} ** 16,
    id: u32 = 0,
    next: u8 = 0,
    hop: u8 = 0,
    due: u64 = 0,
    length: ?usize = null,
    first: bool = false,
    // Original unfragmentable bytes are compared, with payload length omitted.
    prefix_length: usize = 0,
    prefix: [296]u8 = .{0} ** 296,
    present: [capacity]bool = .{false} ** capacity,
    bytes: [capacity]u8 = .{0} ** capacity,
};
pub const Reassembly = struct {
    fragments: [16]Fragment = @splat(.{}),
    pub fn reset(self: *Reassembly, interface: u32, generation: u64) void {
        for (&self.fragments) |*f| if (f.interface == interface and f.generation == generation) {
            f.* = .{};
        };
    }
    pub fn expire(self: *Reassembly, interface: u32, generation: u64, clock: u32, now: u64) void {
        for (&self.fragments) |*f| if (f.active and f.interface == interface and f.generation == generation and (f.clock != clock or now >= f.due)) {
            f.* = .{};
        };
    }
    fn join(self: *Reassembly, interface: u32, generation: u64, clock: u32, now: u64, packet: Packet, prefix: []const u8, id: u32, next: u8, offset: usize, more: bool, bytes: []const u8) Error!Packet {
        if (prefix.len > 296 or bytes.len == 0 or offset > capacity or bytes.len > capacity - offset or more and bytes.len % 8 != 0) return error.Invalid;
        self.expire(interface, generation, clock, now);
        var free: ?*Fragment = null;
        var found: ?*Fragment = null;
        for (&self.fragments) |*f| {
            if (!f.active and free == null) free = f;
            // Fragment identity deliberately excludes Next Header: inconsistent
            // headers for one original datagram discard that whole datagram.
            if (f.active and f.interface == interface and f.generation == generation and f.id == id and std.mem.eql(u8, &f.source, &packet.source) and std.mem.eql(u8, &f.destination, &packet.destination)) found = f;
        }
        const f = found orelse free orelse return error.Capacity;
        if (f.active and f.rejected) return error.Discard;
        if (!f.active) {
            f.* = .{ .active = true, .interface = interface, .generation = generation, .clock = clock, .source = packet.source, .destination = packet.destination, .id = id, .next = next, .hop = packet.hop, .due = now +| 60_000_000_000, .prefix_length = prefix.len };
            @memcpy(f.prefix[0..prefix.len], prefix);
            f.prefix[4] = 0;
            f.prefix[5] = 0;
        } else {
            var original: [296]u8 = .{0} ** 296;
            @memcpy(original[0..prefix.len], prefix);
            original[4] = 0;
            original[5] = 0;
            if (f.next != next or f.prefix_length != prefix.len or !std.mem.eql(u8, f.prefix[0..prefix.len], original[0..prefix.len])) {
                f.rejected = true;
                return error.Invalid;
            }
        }
        const end = offset + bytes.len;
        if (f.length) |length| {
            if (end > length or !more and end != length or more and end >= length) {
                f.rejected = true;
                return error.Invalid;
            }
        }
        if (!more) {
            if (std.mem.indexOfScalar(bool, f.present[end..], true) != null) {
                f.rejected = true;
                return error.Invalid;
            }
            f.length = end;
        }
        if (std.mem.indexOfScalar(bool, f.present[offset..end], true) != null) {
            f.rejected = true;
            return error.Overlap;
        }
        @memcpy(f.bytes[offset..end], bytes);
        @memset(f.present[offset..end], true);
        if (offset == 0) f.first = true;
        const length = f.length orelse return error.Pending;
        if (!f.first or std.mem.indexOfScalar(bool, f.present[0..length], false) != null) return error.Pending;
        var result = packet;
        result.fragmented = true;
        result.next = next;
        result.hop = f.hop;
        result.length = length;
        @memcpy(result.payload[0..length], f.bytes[0..length]);
        f.* = .{};
        return result;
    }
};
pub fn zero(ip: Address) bool {
    return std.mem.allEqual(u8, &ip, 0);
}
pub fn multicast(ip: Address) bool {
    return ip[0] == 0xff;
}
pub fn linkLocal(ip: Address) bool {
    return ip[0] == 0xfe and ip[1] & 0xc0 == 0x80;
}
pub fn mapped(ip: Address) bool {
    return std.mem.allEqual(u8, ip[0..10], 0) and ip[10] == 0xff and ip[11] == 0xff;
}
pub fn loopback(ip: Address) bool {
    return std.mem.allEqual(u8, ip[0..15], 0) and ip[15] == 1;
}
fn invalidMulticast(ip: Address) bool {
    return multicast(ip) and (ip[1] & 15 < 2 or ip[1] & 15 == 15);
}
pub fn same(x: Address, y: Address) bool {
    return std.mem.eql(u8, &x, &y);
}
pub fn prefixMatch(ip: Address, prefix: Address, bits: u32) bool {
    if (bits > 128) return false;
    const whole: usize = @intCast(bits / 8);
    const tail: u3 = @intCast(bits % 8);
    return std.mem.eql(u8, ip[0..whole], prefix[0..whole]) and (tail == 0 or (ip[whole] ^ prefix[whole]) & (@as(u8, 0xff) << @as(u3, @intCast(8 - @as(u4, tail)))) == 0);
}
pub fn solicitedNode(ip: Address) Address {
    var result: Address = .{ 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0 };
    @memcpy(result[13..], ip[13..]);
    return result;
}
fn problem(reject: *Reject, code: u8, pointer: usize, multicast_exception: bool) Error {
    reject.* = .{ .code = code, .pointer = @intCast(pointer), .multicast_exception = multicast_exception };
    return error.ParameterProblem;
}
fn options(bytes: []const u8, start: usize, destination: Address, reject: *Reject) Error!void {
    var pos: usize = 2;
    while (pos < bytes.len) {
        if (bytes[pos] == 0) {
            pos += 1;
            continue;
        }
        if (bytes.len - pos < 2 or @as(usize, bytes[pos + 1]) + 2 > bytes.len - pos) return error.Invalid;
        const len = @as(usize, bytes[pos + 1]) + 2;
        if (bytes[pos] == 1) {
            if (!std.mem.allEqual(u8, bytes[pos + 2 ..][0 .. len - 2], 0)) return error.Invalid;
        } else switch (bytes[pos] >> 6) {
            0 => {},
            1 => return error.Discard,
            2 => return problem(reject, 2, start + pos, true),
            3 => return if (multicast(destination)) error.Discard else problem(reject, 2, start + pos, false),
            else => unreachable,
        }
        pos += len;
    }
}
fn upperMinimum(next: u8, bytes: []const u8) bool {
    return switch (next) {
        6 => bytes.len >= 20 and bytes[12] >> 4 >= 5 and @as(usize, bytes[12] >> 4) * 4 <= bytes.len,
        17 => bytes.len >= 8,
        58 => bytes.len >= 8,
        59 => true,
        else => false,
    };
}
// Parse the chain after the fixed header, and again after reassembly. At most
// eight extension headers and 256 extension bytes; jumbograms are unsupported.
const FragmentView = struct { pos: usize, next: u8, offset: usize, more: bool, id: u32 };
fn walk(packet: *Packet, bytes: []const u8, initial_next: u8, base: usize, allow_fragment: bool, reject: *Reject) Error!?FragmentView {
    var next = initial_next;
    var pos: usize = 0;
    var previous: usize = if (base == 40) 6 else base - 8;
    var count: usize = 0;
    while (next == 0 or next == 60 or next == 43 or next == 44) {
        if (count == 8 or pos > 256) return error.Capacity;
        count += 1;
        if (bytes.len - pos < 8) return error.Invalid;
        const start = pos;
        if (next == 44) {
            if (!allow_fragment) return error.Invalid;
            if (bytes[pos + 1] != 0) return error.Invalid;
            const flags = be16(bytes[pos + 2 ..][0..2]);
            if (flags & 6 != 0) return error.Invalid;
            const fragment: FragmentView = .{ .pos = pos + 8, .next = bytes[pos], .offset = @as(usize, flags & 0xfff8), .more = flags & 1 != 0, .id = be32(bytes[pos + 4 ..][0..4]) };
            // RFC7112: first fragment contains the complete extension chain
            // and upper header. Validate without joining or mutating state.
            if (fragment.offset == 0 and fragment.more) {
                var first = packet.*;
                const nested = walk(&first, bytes[fragment.pos..], fragment.next, base + fragment.pos, false, reject) catch |err| {
                    if (err == error.Invalid) return problem(reject, 3, 0, false);
                    return err;
                };
                if (nested != null or !upperMinimum(first.next, first.payload[0..first.length])) return problem(reject, 3, 0, false);
            }
            return fragment;
        }
        const length = (@as(usize, bytes[pos + 1]) + 1) * 8;
        if (length > bytes.len - pos or pos + length > 256) return error.Invalid;
        if (next == 0) {
            if (base != 40 or pos != 0) return error.Invalid;
            try options(bytes[pos..][0..length], base + pos, packet.destination, reject);
        } else if (next == 60) {
            try options(bytes[pos..][0..length], base + pos, packet.destination, reject);
        } else {
            if (bytes[pos + 2] == 0) return error.Discard;
            if (bytes[pos + 3] != 0) return problem(reject, 0, base + pos + 2, false);
        }
        next = bytes[pos];
        previous = base + start;
        pos += length;
    }
    if (next == 50 or next == 51) return error.Unsupported;
    if (next != 6 and next != 17 and next != 58 and next != 59) return problem(reject, 1, previous, false);
    packet.next = next;
    packet.length = if (next == 59) 0 else bytes.len - pos;
    if (packet.length > capacity) return error.Capacity;
    @memcpy(packet.payload[0..packet.length], bytes[pos..][0..packet.length]);
    return null;
}
pub fn parse(reassembly: *Reassembly, interface: u32, generation: u64, clock: u32, now: u64, bytes: []const u8, reject: *Reject) Error!Packet {
    reject.* = .{};
    if (bytes.len < 40 or bytes[0] >> 4 != 6) return error.Invalid;
    const length: usize = be16(bytes[4..6]);
    if (length > bytes.len - 40 or length > capacity or length == 0 and bytes[6] != 59) return error.Invalid;
    var packet: Packet = .{ .hop = bytes[7] };
    @memcpy(&packet.source, bytes[8..24]);
    @memcpy(&packet.destination, bytes[24..40]);
    if (multicast(packet.source) or zero(packet.destination) or mapped(packet.source) or mapped(packet.destination) or loopback(packet.source) or loopback(packet.destination) or invalidMulticast(packet.destination)) return error.Invalid;
    if (try walk(&packet, bytes[40..][0..length], bytes[6], 40, true, reject)) |f| {
        packet.fragmented = true;
        const remaining = bytes[40 + f.pos ..][0 .. length - f.pos];
        if (f.offset == 0 and !f.more) {
            // RFC6946: atomic fragments neither consume nor poison a queue.
            _ = try walk(&packet, remaining, f.next, 40 + f.pos, false, reject);
        } else {
            packet = try reassembly.join(interface, generation, clock, now, packet, bytes[0 .. 40 + f.pos - 8], f.id, f.next, f.offset, f.more, remaining);
            const joined = packet.payload;
            _ = try walk(&packet, joined[0..packet.length], f.next, 40 + f.pos, false, reject);
        }
    }
    if (packet.fragmented and packet.next == 58 and packet.length > 0 and packet.payload[0] >= 133 and packet.payload[0] <= 137) return error.Discard;
    return packet;
}
pub fn build(source: Address, destination: Address, next: u8, hop: u8, payload: []const u8, output: []u8) Error!usize {
    if (payload.len > 1240 or output.len < 40 + payload.len) return error.Capacity;
    if (zero(destination) or multicast(source) or mapped(source) or mapped(destination) or loopback(source) or loopback(destination) or invalidMulticast(destination) or hop == 0) return error.Invalid;
    @memset(output[0..40], 0);
    output[0] = 0x60;
    var writer = cursor.Writer.init(output[4..6]) catch unreachable;
    writer.writeInt(u16, @intCast(payload.len), .big) catch unreachable;
    output[6] = next;
    output[7] = hop;
    @memcpy(output[8..24], &source);
    @memcpy(output[24..40], &destination);
    @memcpy(output[40..][0..payload.len], payload);
    return 40 + payload.len;
}

fn be16(bytes: []const u8) u16 {
    var reader = cursor.Reader.init(bytes) catch unreachable;
    return reader.readInt(u16, .big) catch unreachable;
}
fn be32(bytes: []const u8) u32 {
    var reader = cursor.Reader.init(bytes) catch unreachable;
    return reader.readInt(u32, .big) catch unreachable;
}
