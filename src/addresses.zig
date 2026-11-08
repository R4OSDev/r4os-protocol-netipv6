//! One interface's authoritative address/prefix/router lifetimes and DAD.
//! The R4P module owns its serial dispatch; callers commit RA candidates whole.
const std = @import("std");
const w = @import("wire.zig");
pub const Error = error{ Invalid, Capacity, Missing, Duplicate, NotReady, NoRoute };
pub const infinite = std.math.maxInt(u64);
const second: u64 = 1_000_000_000;
pub const tentative: u32 = 1;
pub const preferred: u32 = 2;
pub const deprecated: u32 = 4;
pub const duplicate: u32 = 8;
pub const manual: u32 = 16;
pub const slaac: u32 = 32;
pub const link_local: u32 = 64;
pub const Address = struct {
    used: bool = false,
    ip: w.Address = .{0} ** 16,
    flags: u32 = 0,
    bits: u32 = 64,
    preferred_until: u64 = 0,
    valid_until: u64 = 0,
    nonce: [6]u8 = .{0} ** 6,
    nonces: [4][6]u8 = @splat(.{0} ** 6),
    dad_due: u64 = 0,
    dad_sent: u32 = 0,
    loopbacks: u32 = 0,
    loop_seen: bool = false,
    dad_blocked: bool = false,
};
pub const Route = struct {
    used: bool = false,
    prefix: w.Address = .{0} ** 16,
    gateway: w.Address = .{0} ** 16,
    bits: u32 = 0,
    flags: u32 = 0,
    valid_until: u64 = 0,
    unreachable_until: u64 = 0,
};
pub fn eui64(mac: [6]u8) [8]u8 {
    return .{ mac[0] ^ 2, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5] };
}
pub fn expires(now: u64, duration: u64) Error!u64 {
    if (duration == infinite) return infinite;
    return std.math.add(u64, now, duration) catch error.Invalid;
}
pub fn seconds(value: u32) u64 {
    return if (value == std.math.maxInt(u32)) infinite else @as(u64, value) * second;
}
fn normalized(ip: w.Address, bits: u32) w.Address {
    var result = ip;
    for (&result, 0..) |*byte, i| {
        const first = i * 8;
        if (first >= bits) byte.* = 0 else if (first + 8 > bits) byte.* &= @as(u8, 0xff) << @intCast(first + 8 - bits);
    }
    return result;
}
pub const Interface = struct {
    failed: bool = false,
    addresses: [17]Address = @splat(.{}),
    routes: [24]Route = @splat(.{}),
    iid: [8]u8 = .{0} ** 8,
    revision: u64 = 1,
    retransmit: u64 = second,
    mtu: u32 = 1280,
    rs_sent: u32 = 0,
    rs_due: u64 = 0,
    pub fn init(mac: [6]u8, now: u64, nonce: [6]u8) Error!Interface {
        if (mac[0] & 1 != 0 or std.mem.allEqual(u8, &mac, 0)) return error.Invalid;
        var result: Interface = .{ .iid = eui64(mac), .rs_due = now +| @as(u64, std.mem.readInt(u16, nonce[0..2], .little)) * 1_000_000_000 / 65536 };
        var ip: w.Address = .{0} ** 16;
        ip[0] = 0xfe;
        ip[1] = 0x80;
        @memcpy(ip[8..], &result.iid);
        _ = try result.add(ip, 64, link_local, now, infinite, infinite, nonce);
        // RFC4861 treats link-local as on-link independently of RA PIOs.
        result.routes[0] = .{ .used = true, .prefix = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .bits = 10, .flags = 1, .valid_until = infinite };
        return result;
    }
    pub fn find(self: *Interface, ip: w.Address) ?*Address {
        for (&self.addresses) |*a| if (a.used and w.same(a.ip, ip)) return a;
        return null;
    }
    pub fn usable(a: Address, now: u64) bool {
        return a.used and a.flags & (tentative | duplicate) == 0 and now < a.valid_until;
    }
    pub fn owns(self: *const Interface, ip: w.Address, now: u64, include_tentative: bool) bool {
        if (self.failed) return false;
        for (self.addresses) |a| if (a.used and w.same(a.ip, ip) and now < a.valid_until and a.flags & duplicate == 0 and (include_tentative or a.flags & tentative == 0)) return true;
        return false;
    }
    pub fn accepts(self: *const Interface, destination: w.Address, now: u64) bool {
        if (self.failed) return false;
        if (w.same(destination, .{ 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 })) return true;
        for (self.addresses) |a| if (a.used and a.flags & duplicate == 0 and now < a.valid_until and (w.same(destination, a.ip) or w.same(destination, w.solicitedNode(a.ip)))) return true;
        return false;
    }
    pub fn add(self: *Interface, ip: w.Address, bits: u32, origin: u32, now: u64, preferred_duration: u64, valid_duration: u64, nonce: [6]u8) Error!*Address {
        if (self.failed) return error.NotReady;
        if (w.zero(ip) or w.multicast(ip) or w.mapped(ip) or w.loopback(ip) or bits > 128 or valid_duration == 0 or preferred_duration > valid_duration or std.mem.allEqual(u8, &nonce, 0)) return error.Invalid;
        if (self.find(ip) != null) return error.Duplicate;
        const preferred_until = try expires(now, preferred_duration);
        const valid_until = try expires(now, valid_duration);
        for (&self.addresses) |*a| if (!a.used) {
            a.* = .{ .used = true, .ip = ip, .bits = bits, .flags = tentative | origin, .preferred_until = preferred_until, .valid_until = valid_until, .nonce = nonce, .dad_due = now +| @as(u64, std.mem.readInt(u16, nonce[0..2], .little)) * second / 65536 };
            self.revision +|= 1;
            return a;
        };
        return error.Capacity;
    }
    pub fn remove(self: *Interface, ip: w.Address) Error!void {
        const a = self.find(ip) orelse return error.Missing;
        if (a.flags & link_local != 0) return error.Invalid;
        a.* = .{};
        self.revision +|= 1;
        try self.refreshManual();
    }
    pub fn expire(self: *Interface, now: u64) void {
        var manual_expired = false;
        for (&self.addresses) |*a| if (a.used) {
            if (now >= a.valid_until) {
                manual_expired = manual_expired or a.flags & manual != 0;
                a.* = .{};
                self.revision +|= 1;
            } else if (a.flags & (tentative | duplicate) == 0) {
                const status: u32 = if (now >= a.preferred_until) deprecated else preferred;
                const flags = (a.flags & ~(preferred | deprecated)) | status;
                if (flags != a.flags) {
                    a.flags = flags;
                    self.revision +|= 1;
                }
            }
        };
        for (&self.routes) |*r| if (r.used and now >= r.valid_until) {
            r.* = .{};
            self.revision +|= 1;
        };
        if (manual_expired) self.refreshManual() catch unreachable;
    }
    pub fn dadDue(self: *Interface, now: u64) ?*Address {
        if (self.failed) return null;
        self.expire(now);
        for (&self.addresses) |*a| if (a.used and !a.dad_blocked and a.flags & tentative != 0 and a.flags & duplicate == 0 and now >= a.dad_due) {
            if (a.dad_sent > 0 and !a.loop_seen) {
                a.flags = (a.flags & ~tentative) | if (now < a.preferred_until) preferred else deprecated;
                self.revision +|= 1;
            } else if (a.dad_sent == 4) {
                // Conservatively retain tentative/unusable after a persistent
                // loop. Never publish an address on this bounded fallback.
                a.dad_blocked = true;
                self.revision +|= 1;
            } else return a;
        };
        return null;
    }
    pub fn dadSent(self: *Interface, a: *Address, now: u64) void {
        std.debug.assert(a.dad_sent < 4);
        a.nonces[a.dad_sent] = a.nonce;
        a.dad_sent +|= 1;
        a.dad_due = now +| self.retransmit;
        a.loop_seen = false;
    }
    pub fn conflict(self: *Interface, target: w.Address, is_ns: bool, source_unspecified: bool, nonce: ?[6]u8) bool {
        const a = self.find(target) orelse return false;
        if (a.flags & tentative == 0) return false;
        if (is_ns and !source_unspecified) return false;
        if (is_ns and nonce != null) {
            for (a.nonces[0..a.dad_sent]) |sent| if (std.mem.eql(u8, &nonce.?, &sent)) {
                a.loop_seen = true;
                a.loopbacks +|= 1;
                return false;
            };
        }
        a.flags = (a.flags & ~(tentative | preferred | deprecated)) | duplicate;
        self.revision +|= 1;
        // RFC4862: a duplicate EUI64 link-local invalidates this interface.
        if (a.flags & link_local != 0) {
            self.failed = true;
            for (&self.addresses) |*other| if (other.used) {
                other.flags |= duplicate;
            };
        }
        self.refreshManual() catch unreachable;
        return true;
    }
    fn route(self: *Interface, network: w.Address, bits: u32, gateway: w.Address, flags: u32, until: u64) Error!void {
        const key = normalized(network, bits);
        var free: ?*Route = null;
        for (&self.routes) |*r| {
            if (r.used and r.bits == bits and r.flags == flags and w.same(r.prefix, key) and w.same(r.gateway, gateway)) {
                r.valid_until = until;
                r.flags = flags;
                self.revision +|= 1;
                return;
            }
            if (!r.used and free == null) free = r;
        }
        const r = free orelse return error.Capacity;
        r.* = .{ .used = true, .prefix = key, .bits = bits, .gateway = gateway, .flags = flags, .valid_until = until };
        self.revision +|= 1;
    }
    pub fn manualPrefix(self: *Interface, ip: w.Address, bits: u32, until: u64) Error!void {
        _ = ip;
        _ = bits;
        _ = until;
        try self.refreshManual();
    }
    fn refreshManual(self: *Interface) Error!void {
        for (&self.routes) |*r| if (r.used and r.flags & 8 != 0) {
            r.* = .{};
        };
        for (self.addresses) |a| if (a.used and a.flags & manual != 0 and a.flags & duplicate == 0) {
            const key = normalized(a.ip, a.bits);
            var until = a.valid_until;
            for (self.addresses) |other| if (other.used and other.flags & manual != 0 and other.flags & duplicate == 0 and other.bits == a.bits and w.prefixMatch(other.ip, key, a.bits)) {
                until = @max(until, other.valid_until);
            };
            try self.route(key, a.bits, .{0} ** 16, 1 | 8, until);
        };
    }
    pub fn neighborFailed(self: *Interface, ip: w.Address, now: u64) void {
        for (&self.routes) |*r| if (r.used and !w.zero(r.gateway) and w.same(r.gateway, ip)) {
            r.unreachable_until = now +| 30 * second;
            self.revision +|= 1;
        };
    }
    pub fn defaultRouter(self: *const Interface, now: u64) ?w.Address {
        var fallback: ?w.Address = null;
        for (self.routes) |r| if (r.used and r.bits == 0 and now < r.valid_until) {
            if (now >= r.unreachable_until) return r.gateway;
            if (fallback == null) fallback = r.gateway;
        };
        return fallback;
    }
    pub fn router(self: *Interface, ip: w.Address, lifetime: u32, now: u64) Error!void {
        if (self.failed) return error.NotReady;
        if (!w.linkLocal(ip)) return error.Invalid;
        if (lifetime == 0) {
            for (&self.routes) |*r| if (r.used and r.bits == 0 and w.same(r.gateway, ip)) {
                r.* = .{};
                self.revision +|= 1;
            };
            self.rs_sent = 3;
            return;
        }
        try self.route(.{0} ** 16, 0, ip, 2 | 4, try expires(now, seconds(lifetime)));
        self.expire(now);
        self.rs_sent = 3;
    }
    pub fn prefix(self: *Interface, ip: w.Address, bits: u32, flags: u32, valid_seconds: u32, preferred_seconds: u32, now: u64, nonce: [6]u8) Error!void {
        if (self.failed) return error.NotReady;
        if (bits > 128 or w.linkLocal(ip) or w.multicast(ip) or preferred_seconds > valid_seconds) return;
        const valid_duration = seconds(valid_seconds);
        const preferred_duration = seconds(preferred_seconds);
        if (flags & 0x80 != 0) {
            if (valid_duration != 0) try self.route(ip, bits, .{0} ** 16, 1, try expires(now, valid_duration)) else {
                const key = normalized(ip, bits);
                for (&self.routes) |*r| if (r.used and r.bits == bits and r.flags == 1 and w.same(r.prefix, key) and w.zero(r.gateway)) {
                    r.* = .{};
                    self.revision +|= 1;
                };
            }
        }
        // No DHCPv6-PD implementation: RFC9762 requires ignoring P. A remains
        // effective independently of L; only 64-bit EUI64 SLAAC is supported.
        if (flags & 0x40 == 0 or bits != 64) {
            self.expire(now);
            return;
        }
        var address = normalized(ip, 64);
        @memcpy(address[8..], &self.iid);
        if (self.find(address)) |a| {
            if (a.flags & slaac == 0) return;
            const remaining = a.valid_until -| now;
            if (valid_duration > 7200 * second or valid_duration > remaining) a.valid_until = try expires(now, valid_duration) else if (remaining > 7200 * second) a.valid_until = try expires(now, 7200 * second);
            a.preferred_until = try expires(now, preferred_duration);
            self.revision +|= 1;
        } else if (valid_duration != 0) {
            _ = try self.add(address, 64, slaac, now, preferred_duration, valid_duration, nonce);
        }
        self.expire(now);
    }
    pub fn nextHop(self: *const Interface, destination: w.Address, now: u64) Error!w.Address {
        if (w.multicast(destination)) return destination;
        var best: ?Route = null;
        for (self.routes) |r| if (r.used and now < r.valid_until and w.prefixMatch(destination, r.prefix, r.bits) and (best == null or r.bits > best.?.bits or r.bits == best.?.bits and now < best.?.unreachable_until and now >= r.unreachable_until)) {
            best = r;
        };
        const selected = best orelse return error.NoRoute;
        return if (w.zero(selected.gateway)) destination else selected.gateway;
    }
    pub fn selectSource(self: *const Interface, destination: w.Address, now: u64) Error!w.Address {
        if (self.failed) return error.NotReady;
        var best: ?Address = null;
        for (self.addresses) |a| if (usable(a, now)) {
            if (w.linkLocal(destination) or w.multicast(destination) and destination[1] & 15 <= 2) {
                if (a.flags & link_local != 0) return a.ip;
            } else if (a.flags & link_local == 0) {
                if (best == null or best.?.flags & deprecated != 0 and a.flags & preferred != 0 or best.?.flags & deprecated == a.flags & deprecated and w.prefixMatch(destination, a.ip, a.bits) and !w.prefixMatch(destination, best.?.ip, best.?.bits)) best = a;
            }
        };
        return (best orelse return error.NotReady).ip;
    }
};
