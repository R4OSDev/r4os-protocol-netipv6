const std = @import("std");
const w = @import("wire.zig");
const addresses = @import("addresses.zig");
const source: w.Address = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
const destination: w.Address = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 };
fn fragment(offset: u16, more: bool, id: u32, next: u8, data: []const u8, output: []u8) usize {
    var payload: [1240]u8 = .{0} ** 1240;
    payload[0] = next;
    std.mem.writeInt(u16, payload[2..4], offset | @as(u16, @intFromBool(more)), .big);
    std.mem.writeInt(u32, payload[4..8], id, .big);
    @memcpy(payload[8..][0..data.len], data);
    return w.build(source, destination, 44, 64, payload[0 .. 8 + data.len], output) catch unreachable;
}
test "IPv6 bounds and explicit source/destination families; TX is at most1280" {
    var frame: [1600]u8 = .{0xa5} ** 1600;
    const data: [1240]u8 = .{17} ** 1240;
    const length = try w.build(source, destination, 17, 64, &data, &frame);
    try std.testing.expectEqual(@as(usize, 1280), length);
    try std.testing.expectEqual(@as(u8, 0xa5), frame[1280]);
    var queue: w.Reassembly = .{};
    var reject: w.Reject = .{};
    const parsed = try w.parse(&queue, 1, 1, 1, 0, frame[0..length], &reject);
    try std.testing.expectEqualSlices(u8, &data, parsed.payload[0..parsed.length]);
    try std.testing.expectError(error.Invalid, w.parse(&queue, 1, 1, 1, 0, frame[0 .. length - 1], &reject));
    frame[0] = 0x40;
    try std.testing.expectError(error.Invalid, w.parse(&queue, 1, 1, 1, 0, frame[0..length], &reject));
    frame[0] = 0x60;
    frame[8] = 0xff;
    try std.testing.expectError(error.Invalid, w.parse(&queue, 1, 1, 1, 0, frame[0..length], &reject));
    var large: [1241]u8 = .{0} ** 1241;
    try std.testing.expectError(error.Capacity, w.build(source, destination, 17, 64, &large, &frame));
}
test "Hop-by-hop and destination options obey all four unknown action classes" {
    var payload: [16]u8 = .{0} ** 16;
    payload[0] = 17;
    payload[1] = 0;
    payload[2] = 0x20;
    payload[3] = 2;
    var frame: [1280]u8 = undefined;
    const length = try w.build(source, destination, 0, 64, &payload, &frame);
    var queue: w.Reassembly = .{};
    var reject: w.Reject = .{};
    try std.testing.expectEqual(@as(u8, 17), (try w.parse(&queue, 1, 1, 1, 0, frame[0..length], &reject)).next);
    frame[42] = 0x60;
    try std.testing.expectError(error.Discard, w.parse(&queue, 1, 1, 1, 0, frame[0..length], &reject));
    frame[42] = 0xa0;
    try std.testing.expectError(error.ParameterProblem, w.parse(&queue, 1, 1, 1, 0, frame[0..length], &reject));
    try std.testing.expectEqual(@as(u32, 42), reject.pointer);
    try std.testing.expect(reject.multicast_exception);
    frame[42] = 0xe0;
    frame[24] = 0xff;
    frame[25] = 2;
    try std.testing.expectError(error.Discard, w.parse(&queue, 1, 1, 1, 0, frame[0..length], &reject));
    frame[24] = destination[0];
    frame[25] = destination[1];
    frame[42] = 1;
    frame[44] = 1;
    try std.testing.expectError(error.Invalid, w.parse(&queue, 1, 1, 1, 0, frame[0..length], &reject));
}
test "fragment reassembly out of order includes at least1500 and exact interface identity" {
    var data: [1460]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);
    var frame: [1280]u8 = undefined;
    var queue: w.Reassembly = .{};
    var reject: w.Reject = .{};
    var length = fragment(1200, false, 7, 17, data[1200..], &frame);
    try std.testing.expectError(error.Pending, w.parse(&queue, 1, 9, 1, 0, frame[0..length], &reject));
    length = fragment(0, true, 7, 17, data[0..1200], &frame);
    try std.testing.expectError(error.Pending, w.parse(&queue, 2, 9, 1, 0, frame[0..length], &reject));
    const packet = try w.parse(&queue, 1, 9, 1, 0, frame[0..length], &reject);
    try std.testing.expect(packet.fragmented);
    try std.testing.expectEqualSlices(u8, &data, packet.payload[0..packet.length]);
}
test "overlap poisons complete datagram until60seconds; atomic fragment is independent" {
    const data: [16]u8 = .{8} ** 16;
    var frame: [1280]u8 = undefined;
    var queue: w.Reassembly = .{};
    var reject: w.Reject = .{};
    var length = fragment(0, true, 7, 17, &data, &frame);
    try std.testing.expectError(error.Pending, w.parse(&queue, 1, 9, 1, 0, frame[0..length], &reject));
    try std.testing.expectError(error.Overlap, w.parse(&queue, 1, 9, 1, 1, frame[0..length], &reject));
    length = fragment(16, false, 7, 17, &data, &frame);
    try std.testing.expectError(error.Discard, w.parse(&queue, 1, 9, 1, 2, frame[0..length], &reject));
    length = fragment(0, false, 7, 17, &data, &frame);
    try std.testing.expect((try w.parse(&queue, 1, 9, 1, 3, frame[0..length], &reject)).fragmented);
    length = fragment(0, true, 7, 17, &data, &frame);
    try std.testing.expectError(error.Pending, w.parse(&queue, 1, 9, 1, 60_000_000_000, frame[0..length], &reject));
}
test "first fragment must contain whole upper header; fragmented ND never accepted" {
    var data: [16]u8 = .{0} ** 16;
    var frame: [1280]u8 = undefined;
    var queue: w.Reassembly = .{};
    var reject: w.Reject = .{};
    var length = fragment(0, true, 3, 6, &data, &frame);
    try std.testing.expectError(error.ParameterProblem, w.parse(&queue, 1, 9, 1, 0, frame[0..length], &reject));
    try std.testing.expectEqual(@as(u8, 3), reject.code);
    data[0] = 135;
    length = fragment(0, false, 3, 58, &data, &frame);
    try std.testing.expectError(error.Discard, w.parse(&queue, 1, 9, 1, 0, frame[0..length], &reject));
}
test "reassembly has bounded capacity and exact clock/link retirement" {
    const data: [16]u8 = .{0} ** 16;
    var frame: [1280]u8 = undefined;
    var queue: w.Reassembly = .{};
    var reject: w.Reject = .{};
    for (0..16) |i| {
        const length = fragment(0, true, @intCast(i), 17, &data, &frame);
        try std.testing.expectError(error.Pending, w.parse(&queue, 1, 9, 1, 0, frame[0..length], &reject));
    }
    const length = fragment(0, true, 99, 17, &data, &frame);
    try std.testing.expectError(error.Capacity, w.parse(&queue, 1, 9, 1, 0, frame[0..length], &reject));
    queue.reset(1, 10);
    try std.testing.expectError(error.Capacity, w.parse(&queue, 1, 9, 1, 0, frame[0..length], &reject));
    try std.testing.expectError(error.Pending, w.parse(&queue, 1, 9, 2, 0, frame[0..length], &reject));
}

test "DAD never publishes tentative, reflected or duplicated EUI64 address" {
    const nonce: [6]u8 = .{ 1, 2, 3, 4, 5, 6 };
    var iface = try addresses.Interface.init(.{ 2, 3, 4, 5, 6, 7 }, 0, nonce);
    const ll = iface.addresses[0].ip;
    try std.testing.expect(!iface.owns(ll, 0, false));
    try std.testing.expectError(error.NotReady, iface.selectSource(ll, 0));
    const dad = iface.dadDue(1_000_000_000).?;
    iface.dadSent(dad, 1_000_000_000);
    try std.testing.expect(!iface.conflict(ll, true, true, nonce));
    try std.testing.expect(!iface.owns(ll, 1_000_000_001, false));
    const retry = iface.dadDue(2_000_000_000).?;
    retry.nonce[5] += 1;
    iface.dadSent(retry, 2_000_000_000);
    // Old reflected probes match the retained nonce set as well.
    try std.testing.expect(!iface.conflict(ll, true, true, nonce));
    try std.testing.expect(iface.dadDue(3_000_000_000) != null);
    try std.testing.expect(iface.conflict(ll, false, false, null));
    try std.testing.expect(iface.addresses[0].flags & addresses.duplicate != 0);
    try std.testing.expect(!iface.owns(ll, 3_000_000_000, true));
    try std.testing.expect(iface.failed);
    try std.testing.expectError(error.NotReady, iface.add(source, 64, addresses.manual, 3_000_000_000, 100, 200, nonce));
    try std.testing.expectError(error.NotReady, iface.prefix(source, 64, 0xc0, 7200, 3600, 3_000_000_000, nonce));
}
test "DAD completes after acknowledged probe and full real retransmit interval" {
    var iface = try addresses.Interface.init(.{ 2, 3, 4, 5, 6, 7 }, 0, .{ 1, 2, 3, 4, 5, 6 });
    const ll = iface.addresses[0].ip;
    const a = iface.dadDue(1_000_000_000).?;
    // Busy/failed TX leaves the probe eligible, and the address unusable.
    try std.testing.expect(iface.dadDue(2_000_000_000) != null);
    iface.dadSent(a, 2_000_000_000);
    try std.testing.expect(iface.dadDue(2_999_999_999) == null);
    try std.testing.expect(!iface.owns(ll, 2_999_999_999, false));
    try std.testing.expect(iface.dadDue(3_000_000_000) == null);
    try std.testing.expect(iface.owns(ll, 3_000_000_000, false));
}
test "SLAAC A and onlink L independent; valid lifetime two-hour rule and preferred expiry" {
    const second: u64 = 1_000_000_000;
    const nonce: [6]u8 = .{ 1, 2, 3, 4, 5, 6 };
    var iface = try addresses.Interface.init(.{ 2, 3, 4, 5, 6, 7 }, 0, nonce);
    var prefix = source;
    prefix[15] = 0;
    try iface.prefix(prefix, 64, 0x40 | 0x10, 20_000, 10_000, 0, nonce);
    try std.testing.expectEqual(@as(u32, addresses.slaac | addresses.tentative), iface.addresses[1].flags);
    try std.testing.expectError(error.NoRoute, iface.nextHop(source, 0));
    // P is ignored because this host has no DHCPv6-PD (RFC9762 section7.1).
    try iface.prefix(prefix, 64, 0xc0, 1, 0, 0, nonce);
    try std.testing.expectEqual(@as(u64, 7200 * second), iface.addresses[1].valid_until);
    iface.addresses[1].flags &= ~addresses.tentative;
    iface.expire(second);
    try std.testing.expect(iface.addresses[1].flags & addresses.deprecated != 0);
    try std.testing.expect(iface.addresses[1].used);
    try iface.prefix(prefix, 64, 0x40, 0, 0, second, nonce);
    try std.testing.expectEqual(@as(u64, 7200 * second), iface.addresses[1].valid_until);
    iface.expire(7200 * second);
    try std.testing.expect(!iface.addresses[1].used);
}
test "default routes retain independent routers and withdraw without slot admission" {
    var iface = try addresses.Interface.init(.{ 2, 3, 4, 5, 6, 7 }, 0, .{ 1, 2, 3, 4, 5, 6 });
    var r1: w.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    var r2 = r1;
    r2[15] = 2;
    try iface.router(r1, 10, 0);
    try iface.router(r2, 20, 0);
    try std.testing.expectEqual(r1, try iface.nextHop(source, 0));
    iface.neighborFailed(r1, 0);
    try std.testing.expectEqual(r2, try iface.nextHop(source, 0));
    try std.testing.expectEqual(r2, iface.defaultRouter(0).?);
    try iface.router(r1, 0, 0);
    try std.testing.expectEqual(r2, try iface.nextHop(source, 0));
    iface.expire(20_000_000_000);
    try std.testing.expectError(error.NoRoute, iface.nextHop(source, 20_000_000_000));
    r1[15] = 9;
    try iface.router(r1, 0, 20_000_000_000);
}
test "manual prefix lifetime follows all owned addresses and survives RA withdrawal" {
    const nonce: [6]u8 = .{ 1, 2, 3, 4, 5, 6 };
    var iface = try addresses.Interface.init(.{ 2, 3, 4, 5, 6, 7 }, 0, nonce);
    var first = source;
    first[15] = 4;
    var last = source;
    last[15] = 5;
    _ = try iface.add(first, 64, addresses.manual, 0, 50, 100, nonce);
    try iface.manualPrefix(first, 64, 100);
    _ = try iface.add(last, 64, addresses.manual, 0, 100, 200, nonce);
    try iface.manualPrefix(last, 64, 200);
    try iface.prefix(source, 64, 0x80, 10, 0, 0, nonce);
    try iface.prefix(source, 64, 0x80, 0, 0, 0, nonce);
    iface.expire(100);
    try std.testing.expectEqual(source, try iface.nextHop(source, 100));
    try iface.remove(last);
    try std.testing.expectError(error.NoRoute, iface.nextHop(source, 100));
}
