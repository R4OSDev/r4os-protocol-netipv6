//! External IPv6 owner over copied, admitted original PPI/link mechanisms.
const std = @import("std");
const sdk = @import("r4os");
const a = sdk.abi;
const common = sdk.network_family.common;
const w = @import("wire.zig");
const address = @import("addresses.zig");
var api: ?sdk.technical2.Protocol = null;
const Link = struct {
    present: bool = false,
    ready: bool = false,
    info: a.NetworkLinkInfo = .{},
    state: address.Interface = .{},
    last_ns: u64 = 0,
    rx: u64 = 0,
    tx: u64 = 0,
    dropped: u64 = 0,
    error_after: u64 = 0,
    entropy_generation: u64 = 0,
};
const Queued = struct { used: bool = false, interface: u32 = 0, generation: u64 = 0, serial: u64 = 0, packet: w.Packet = .{} };
var links: [8]Link = @splat(.{});
var reassembly: w.Reassembly = .{};
var queue: [16]Queued = @splat(.{});
var serial: u64 = 0;
const Clock = struct {
    info: a.MonotonicClockInfo,
    pub fn monotonicClock(self: Clock, output: *a.MonotonicClockInfo) i32 {
        output.* = self.info;
        return 1;
    }
};
comptime {
    asm (sdk.technical2.protocolEntriesAsm("ipv6_init", "ipv6_shutdown", "ipv6_query", "ipv6_dispatch"));
    std.debug.assert(address.tentative == a.ipv6_address_flag_tentative and address.link_local == a.ipv6_address_flag_link_local);
}
fn fail(err: anyerror) i32 {
    return switch (err) {
        error.Capacity => a.network_error_capacity,
        error.Missing, error.NoRoute => a.network_error_not_found,
        error.Unsupported => a.network_error_unsupported_policy,
        error.NotReady, error.Pending => a.network_error_would_block,
        error.ClockChanged, error.ClockUnavailable => a.network_error_clock_changed,
        error.Timeout => a.network_error_timeout,
        error.ProviderChanged => a.network_error_provider_changed,
        error.Backend => a.network_error_backend,
        else => a.network_error_invalid,
    };
}
export fn ipv6_init(raw: *const a.ProtocolApi2) callconv(.c) i32 {
    const view = sdk.technical2.Protocol.init(raw) orelse return a.network_error_backend;
    if (view.function("protocol_dispatch") == null or view.function("link_io") == null or view.function("entropy_fill") == null) return a.err_no_fn;
    const register = view.function("register_role") orelse return a.err_no_fn;
    const status = view.function("set_status") orelse return a.err_no_fn;
    if (register("net.ipv6", @intFromEnum(a.ProtocolCategory.net), 0) != 0) return a.network_error_backend;
    links = @splat(.{});
    queue = @splat(.{});
    reassembly = .{};
    serial = 0;
    api = view;
    return status(@intFromEnum(a.ProtocolState.active), "Bounded IPv6 host; endpoint IPv6 capability qualified separately");
}
export fn ipv6_shutdown() callconv(.c) i32 {
    links = @splat(.{});
    queue = @splat(.{});
    reassembly = .{};
    api = null;
    return 0;
}
export fn ipv6_query(out: *a.ProtocolStatus) callconv(.c) i32 {
    out.* = .{ .state = @intFromEnum(if (api != null) a.ProtocolState.active else a.ProtocolState.err) };
    return 0;
}
fn rpc(comptime Request: type, comptime Reply: type, role: []const u8, op: u32, request: *const Request, reply: *Reply) i32 {
    const view = api orelse return a.network_error_backend;
    const dispatch = view.function("protocol_dispatch") orelse return a.err_no_fn;
    var input: a.ProtocolBuffer = .{ .data = @constCast(request), .len = @sizeOf(Request), .capacity = @sizeOf(Request) };
    var value: Reply = undefined;
    var output: a.ProtocolBuffer = .{ .data = &value, .capacity = @sizeOf(Reply) };
    const code = dispatch(role.ptr, @intCast(role.len), op, &input, &output);
    if (code != 0) return code;
    if (output.len != @sizeOf(Reply) or value.version != 1 or value.size != @sizeOf(Reply)) return a.network_error_backend;
    reply.* = value;
    return 0;
}
fn nonce() error{Backend}![6]u8 {
    const view = api orelse return error.Backend;
    const fill = view.function("entropy_fill") orelse return error.Backend;
    var value: [6]u8 = undefined;
    if (fill(&value, value.len) != value.len or std.mem.allEqual(u8, &value, 0)) return error.Backend;
    return value;
}
fn entropyGeneration() error{Backend}!?u64 {
    const view = api orelse return error.Backend;
    const snapshot = view.function("entropy_source_info") orelse return null;
    var source: a.EntropySourceInfo = .{};
    // Busy/unreadable is not evidence of source removal. Preserve the old
    // interface on that error; only an actual unavailable snapshot retires it.
    if (snapshot(&source) != 0 or source.version != 1 or source.size != @sizeOf(a.EntropySourceInfo) or source.reserved0 != 0 or source.reserved1 != 0) return error.Backend;
    if (source.state != a.entropy_state_ready or source.flags & a.entropy_source_flag_registered == 0 or source.generation == 0) return null;
    return source.generation;
}
fn ndRequest(link: *const Link) a.NdpRequest {
    return .{ .interface_id = link.info.interface_id, .generation = link.info.generation, .clock_generation = link.info.clock.generation, .now_ns = link.info.clock.instant_ns };
}
fn nd(link: *const Link, op: u32, target: w.Address, flags: u32, out: *a.NdpEvent) i32 {
    var request = ndRequest(link);
    request.target = target;
    request.flags = flags;
    return rpc(a.NdpRequest, a.NdpEvent, "net.ndp", op, &request, out);
}
fn clear(link: *Link) void {
    if (link.present) {
        var ignored: a.NdpEvent = .{};
        if (link.info.clock.generation != 0) _ = nd(link, a.ndp_op_link_reset, .{0} ** 16, 0, &ignored);
        reassembly.reset(link.info.interface_id, link.info.generation);
        for (&queue) |*entry| if (entry.used and entry.interface == link.info.interface_id and entry.generation == link.info.generation) {
            entry.* = .{};
        };
    }
    link.* = .{};
}
fn clockSame(x: a.MonotonicClockInfo, y: a.MonotonicClockInfo) bool {
    return x.source == y.source and x.generation == y.generation and x.event_backend == y.event_backend and x.event_requested_hz == y.event_requested_hz;
}
fn sync(index: usize) error{ Missing, Backend, ClockChanged }!*Link {
    if (index >= links.len) return error.Missing;
    const view = api orelse return error.Backend;
    const callback = view.function("link_io") orelse return error.Backend;
    const request: a.NetworkLinkRequest = .{ .op = a.network_link_op_info, .index = @intCast(index) };
    var info: a.NetworkLinkInfo = .{};
    const code = callback(&request, &info);
    const link = &links[index];
    if (code != 0) {
        if (code == a.network_error_not_found or code == a.network_error_provider_changed) {
            clear(link);
            return error.Missing;
        }
        return error.Backend;
    }
    if (info.version != 1 or info.size != @sizeOf(a.NetworkLinkInfo) or info.index != index or info.provider == 0 or info.interface_id == 0 or info.generation == 0 or info.reserved != 0 or info.flags & ~@as(u32, 15) != 0) return error.Backend;
    const sample = common.sample(Clock{ .info = info.clock }) catch null;
    const entropy_generation = try entropyGeneration();
    const ready = entropy_generation != null and sample != null and info.flags & (a.network_link_flag_available | a.network_link_flag_up | a.network_link_flag_multicast | a.network_link_flag_clock_valid) == (a.network_link_flag_available | a.network_link_flag_up | a.network_link_flag_multicast | a.network_link_flag_clock_valid) and info.mtu >= 1280;
    const changed = link.present and (link.info.interface_id != info.interface_id or link.info.generation != info.generation or link.info.provider != info.provider or !std.mem.eql(u8, &link.info.mac, &info.mac) or link.ready != ready or link.entropy_generation != (entropy_generation orelse 0) or link.ready and (!clockSame(link.info.clock, info.clock) or info.clock.instant_ns < link.last_ns));
    if (changed) clear(link);
    if (!link.present) {
        link.* = .{ .present = true, .info = info, .entropy_generation = entropy_generation orelse 0 };
        if (ready) link.state = address.Interface.init(info.mac, info.clock.instant_ns, nonce() catch return error.Backend) catch return error.Backend;
        link.ready = ready;
    }
    link.info = info;
    link.last_ns = info.clock.instant_ns;
    if (link.ready) {
        link.state.expire(info.clock.instant_ns);
        reassembly.expire(info.interface_id, info.generation, info.clock.generation, info.clock.instant_ns);
    }
    // Clock/identity loss invalidates old state before another packet can use
    // it. A query may then discover the newly tentative interface state.
    return link;
}
fn emit(link: *Link, source: w.Address, destination: w.Address, next: u8, hop: u8, payload: []const u8, mac: [6]u8) i32 {
    if (!link.ready or link.state.failed) return a.network_error_unsupported_policy;
    const view = api orelse return a.network_error_backend;
    const callback = view.function("link_io") orelse return a.err_no_fn;
    var request: a.NetworkLinkRequest = .{ .op = a.network_link_op_transmit, .index = link.info.index, .interface_id = link.info.interface_id, .generation = link.info.generation };
    @memcpy(request.frame[0..6], &mac);
    @memcpy(request.frame[6..12], &link.info.mac);
    request.frame[12] = 0x86;
    request.frame[13] = 0xdd;
    const length = w.build(source, destination, next, hop, payload, request.frame[14..]) catch |err| return fail(err);
    request.bytes = @intCast(@max(60, 14 + length));
    var reply: a.NetworkLinkInfo = .{};
    const result = callback(&request, &reply);
    if (result == 0) link.tx +|= 1;
    return result;
}
fn multicastMac(ip: w.Address) [6]u8 {
    return .{ 0x33, 0x33, ip[12], ip[13], ip[14], ip[15] };
}
fn icmp(link: *Link, op: u32, source: w.Address, destination: w.Address, payload: []const u8, reply_source: w.Address, out: *a.Icmpv6Message) i32 {
    _ = link;
    if (payload.len > 1500) return a.network_error_capacity;
    var request: a.Icmpv6Message = .{ .source = source, .destination = destination, .reply_source = reply_source, .bytes = @intCast(payload.len) };
    @memcpy(request.payload[0..payload.len], payload);
    return rpc(a.Icmpv6Message, a.Icmpv6Message, "net.icmpv6", op, &request, out);
}
fn sendIcmp(link: *Link, source: w.Address, destination: w.Address, bytes: []const u8, mac: [6]u8) i32 {
    var sealed: a.Icmpv6Message = .{};
    const code = icmp(link, a.icmpv6_op_seal, source, destination, bytes, .{0} ** 16, &sealed);
    if (code != 0) return code;
    return emit(link, source, destination, 58, 255, sealed.payload[0..sealed.bytes], mac);
}
fn probe(link: *Link, event: a.NdpEvent) i32 {
    if (event.kind != a.ndp_action_multicast_probe and event.kind != a.ndp_action_unicast_probe) return a.network_error_invalid;
    const source = link.state.selectSource(.{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, link.info.clock.instant_ns) catch |err| return fail(err);
    const destination = if (event.kind == a.ndp_action_multicast_probe) w.solicitedNode(event.target) else event.target;
    var bytes: [32]u8 = .{0} ** 32;
    bytes[0] = 135;
    @memcpy(bytes[8..24], &event.target);
    bytes[24] = 1;
    bytes[25] = 1;
    @memcpy(bytes[26..32], &link.info.mac);
    const code = sendIcmp(link, source, destination, &bytes, if (event.kind == a.ndp_action_multicast_probe) multicastMac(destination) else event.mac);
    if (code != 0) return code;
    var acknowledged: a.NdpEvent = .{};
    return nd(link, a.ndp_op_confirm, event.target, a.ndp_confirm_probe_sent, &acknowledged);
}
fn tick(link: *Link) void {
    if (!link.ready or link.state.failed) return;
    const now = link.info.clock.instant_ns;
    if (link.state.dadDue(now)) |dad| {
        // Every transmitted Enhanced-DAD probe has its own entropy nonce.
        dad.nonce = nonce() catch return;
        for (dad.nonces[0..dad.dad_sent]) |sent| if (std.mem.eql(u8, &sent, &dad.nonce)) return;
        const destination = w.solicitedNode(dad.ip);
        var bytes: [32]u8 = .{0} ** 32;
        bytes[0] = 135;
        @memcpy(bytes[8..24], &dad.ip);
        bytes[24] = 14;
        bytes[25] = 1;
        @memcpy(bytes[26..32], &dad.nonce);
        if (sendIcmp(link, .{0} ** 16, destination, &bytes, multicastMac(destination)) == 0) link.state.dadSent(dad, now);
        return;
    }
    if (link.state.rs_sent < 3 and now >= link.state.rs_due) {
        const destination: w.Address = .{ 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
        const source = link.state.selectSource(destination, now) catch return;
        var bytes: [16]u8 = .{0} ** 16;
        bytes[0] = 133;
        bytes[8] = 1;
        bytes[9] = 1;
        @memcpy(bytes[10..16], &link.info.mac);
        if (sendIcmp(link, source, destination, &bytes, multicastMac(destination)) == 0) {
            link.state.rs_sent += 1;
            link.state.rs_due = now +| 4_000_000_000;
        }
    }
    var event: a.NdpEvent = .{};
    if (nd(link, a.ndp_op_tick, .{0} ** 16, 0, &event) == 0) {
        if (event.kind == a.ndp_action_multicast_probe or event.kind == a.ndp_action_unicast_probe) _ = probe(link, event);
        if (event.kind == a.ndp_action_timed_out) link.state.neighborFailed(event.target, now);
    }
}
fn networkAddress(link: *const Link, ip: w.Address) a.NetworkAddress {
    return .{ .family = 6, .interface_id = link.info.interface_id, .scope_id = if (w.linkLocal(ip) or w.multicast(ip) and ip[1] & 15 <= 2) link.info.interface_id else 0, .bytes = ip };
}
fn validAddress(link: *const Link, value: a.NetworkAddress) bool {
    return common.addressValid(value) and value.family == 6 and value.interface_id == link.info.interface_id and value.scope_id == networkAddress(link, value.bytes).scope_id and !w.mapped(value.bytes);
}
fn find(interface: u32, generation: u64, provider: u64) error{ ProviderChanged, Backend }!*Link {
    for (0..links.len) |i| {
        const link = sync(i) catch |err| {
            if (err == error.Missing) break else return error.Backend;
        };
        if (link.info.interface_id == interface) {
            if (link.info.generation != generation or link.info.provider != provider) return error.ProviderChanged;
            return link;
        }
    }
    return error.ProviderChanged;
}
fn interfaceInfo(link: *const Link) a.Ipv6InterfaceInfo {
    var out: a.Ipv6InterfaceInfo = .{ .link = link.info, .revision = link.state.revision, .max_packet = if (link.ready) 1280 else 0, .rx_packets = link.rx, .tx_packets = link.tx, .dropped_packets = link.dropped };
    if (!link.ready) return out;
    if (link.state.failed) out.max_packet = 0 else out.capabilities = a.ipv6_cap_packet | a.ipv6_cap_icmp | a.ipv6_cap_nd | a.ipv6_cap_dad | a.ipv6_cap_slaac | a.ipv6_cap_extensions | a.ipv6_cap_reassembly | a.ipv6_cap_static_address;
    for (link.state.addresses) |row| if (row.used) {
        out.address_count += 1;
        if (row.flags & address.link_local != 0) out.link_local = networkAddress(link, row.ip);
        if (address.Interface.usable(row, link.last_ns) and row.flags & address.link_local == 0 and (out.preferred.family == 0 or row.flags & address.preferred != 0)) out.preferred = networkAddress(link, row.ip);
        if (row.flags & address.tentative != 0 and !row.dad_blocked and (out.next_due_ns == 0 or row.dad_due < out.next_due_ns)) out.next_due_ns = row.dad_due;
    };
    for (link.state.routes) |row| if (row.used) {
        out.route_count += 1;
    };
    if (link.state.defaultRouter(link.last_ns)) |router| out.default_router = networkAddress(link, router);
    return out;
}
fn store(comptime T: type, value: *const T, output: *a.ProtocolBuffer) i32 {
    if (output.data == null or output.capacity < @sizeOf(T)) return a.network_error_capacity;
    const bytes: [*]u8 = @ptrCast(output.data.?);
    @memcpy(bytes[0..@sizeOf(T)], std.mem.asBytes(value));
    output.len = @sizeOf(T);
    return 0;
}
fn load(comptime T: type, input: *const a.ProtocolBuffer) ?T {
    if (input.data == null or input.len != @sizeOf(T)) return null;
    var value: T = undefined;
    const bytes: [*]const u8 = @ptrCast(input.data.?);
    @memcpy(std.mem.asBytes(&value), bytes[0..@sizeOf(T)]);
    if (value.version != 1 or value.size != @sizeOf(T)) return null;
    return value;
}
fn ndReceive(link: *Link, packet: *const w.Packet, mac: [6]u8) i32 {
    var request = ndRequest(link);
    request.source = packet.source;
    request.destination = packet.destination;
    request.mac = mac;
    request.hop_limit = packet.hop;
    request.bytes = @intCast(packet.length);
    request.flags = if (packet.fragmented) a.ndp_request_fragmented else 0;
    @memcpy(request.payload[0..packet.length], packet.payload[0..packet.length]);
    var event: a.NdpEvent = .{};
    var code = rpc(a.NdpRequest, a.NdpEvent, "net.ndp", a.ndp_op_handle_rx, &request, &event);
    if (code != 0) return code;
    if (event.kind == 135 or event.kind == 136) {
        if (event.kind == 136 and event.flags & a.ndp_event_flag_router == 0) {
            for (link.state.routes) |route| if (route.used and route.bits == 0 and w.same(route.gateway, event.target)) {
                link.state.router(event.target, 0, link.last_ns) catch {};
                break;
            };
        }
        const conflict = link.state.conflict(event.target, event.kind == 135, w.zero(packet.source), if (event.flags & a.ndp_event_flag_nonce_present != 0) event.nonce else null);
        if (conflict) {
            if (link.state.failed) {
                reassembly.reset(link.info.interface_id, link.info.generation);
                for (&queue) |*entry| if (entry.used and entry.interface == link.info.interface_id and entry.generation == link.info.generation) {
                    entry.* = .{};
                };
                var ignored: a.NdpEvent = .{};
                _ = nd(link, a.ndp_op_link_reset, .{0} ** 16, 0, &ignored);
            }
            return 0;
        }
        if (event.kind == 135 and link.state.owns(event.target, link.last_ns, false)) {
            const destination = if (w.zero(packet.source)) w.Address{ 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } else packet.source;
            var bytes: [32]u8 = .{0} ** 32;
            bytes[0] = 136;
            std.mem.writeInt(u32, bytes[4..8], a.ndp_event_flag_override | (if (w.zero(packet.source)) @as(u32, 0) else a.ndp_event_flag_solicited), .big);
            @memcpy(bytes[8..24], &event.target);
            bytes[24] = 2;
            bytes[25] = 1;
            @memcpy(bytes[26..32], &link.info.mac);
            code = sendIcmp(link, event.target, destination, &bytes, if (w.zero(packet.source)) multicastMac(destination) else mac);
        }
    } else if (event.kind == 134) {
        if (!w.multicast(packet.destination) and !link.state.owns(packet.destination, link.last_ns, false)) return a.network_error_invalid;
        var candidate = link.state;
        candidate.router(event.target, event.router_lifetime_seconds, link.last_ns) catch |err| return fail(err);
        for (event.prefixes[0..event.prefix_count]) |p| candidate.prefix(p.bytes, p.prefix_length, p.flags, p.valid_lifetime_seconds, p.preferred_lifetime_seconds, link.last_ns, nonce() catch return a.network_error_backend) catch |err| return fail(err);
        if (event.retransmit_ms != 0) candidate.retransmit = @as(u64, event.retransmit_ms) * 1_000_000;
        if (event.mtu >= 1280 and event.mtu <= link.info.mtu) candidate.mtu = event.mtu;
        link.state = candidate;
    }
    return code;
}
fn checksum(packet: *const w.Packet) i32 {
    if (packet.next == 17 and (packet.length < 8 or std.mem.readInt(u16, packet.payload[4..6], .big) != packet.length or packet.payload[6] == 0 and packet.payload[7] == 0)) return a.network_error_invalid;
    if (packet.next == 6 and (packet.length < 20 or packet.payload[12] >> 4 < 5 or @as(usize, packet.payload[12] >> 4) * 4 > packet.length)) return a.network_error_invalid;
    var request: a.Icmpv6Message = .{ .source = packet.source, .destination = packet.destination, .bytes = @intCast(packet.length), .next_header = packet.next };
    @memcpy(request.payload[0..packet.length], packet.payload[0..packet.length]);
    var result: a.Icmpv6Message = .{};
    const code = rpc(a.Icmpv6Message, a.Icmpv6Message, "net.icmpv6", if (packet.next == 58) a.icmpv6_op_parse else a.icmpv6_op_checksum, &request, &result);
    if (code != 0) return code;
    return if (result.checksum == 0) 0 else a.network_error_invalid;
}
fn invokingError(bytes: []const u8) bool {
    if (bytes.len < 40) return true;
    var next = bytes[6];
    var pos: usize = 40;
    var count: usize = 0;
    while (next == 0 or next == 43 or next == 60 or next == 44) {
        if (count == 8 or bytes.len - pos < 8) return true;
        count += 1;
        const length = if (next == 44) @as(usize, 8) else (@as(usize, bytes[pos + 1]) + 1) * 8;
        if (length > bytes.len - pos) return true;
        if (next == 44 and std.mem.readInt(u16, bytes[pos + 2 ..][0..2], .big) & 0xfff8 != 0) return true;
        next = bytes[pos];
        pos += length;
    }
    return next == 58 and (pos == bytes.len or bytes[pos] < 128);
}
fn parameterProblem(link: *Link, quote: []const u8, reject: w.Reject, mac: [6]u8) void {
    if (quote.len < 40 or link.last_ns < link.error_after or invokingError(quote)) return;
    var peer: w.Address = undefined;
    @memcpy(&peer, quote[8..24]);
    if (w.zero(peer) or w.multicast(peer)) return;
    var destination: w.Address = undefined;
    @memcpy(&destination, quote[24..40]);
    const source = if (!w.multicast(destination) and link.state.owns(destination, link.last_ns, false)) destination else link.state.selectSource(peer, link.last_ns) catch return;
    var request: a.Icmpv6Message = .{ .source = source, .destination = peer, .bytes = @intCast(8 + @min(quote.len, 1492)), .flags = if (reject.multicast_exception) 1 else 0 };
    request.payload[0] = 4;
    request.payload[1] = reject.code;
    std.mem.writeInt(u32, request.payload[4..8], reject.pointer, .big);
    @memcpy(request.payload[8..request.bytes], quote[0 .. request.bytes - 8]);
    var reply: a.Icmpv6Message = .{};
    if (rpc(a.Icmpv6Message, a.Icmpv6Message, "net.icmpv6", a.icmpv6_op_error, &request, &reply) != 0) return;
    if (emit(link, reply.source, reply.destination, 58, 64, reply.payload[0..reply.bytes], mac) == 0) link.error_after = link.last_ns +| 100_000_000;
}
fn receiveFrame(request: a.Ipv6FrameOp) i32 {
    if (request.reserved != 0 or request.bytes < 54 or request.bytes > request.frame.len or request.link.provider != 0 or !std.mem.allEqual(u8, request.frame[request.bytes..], 0)) return a.network_error_invalid;
    if (request.link.version != 1 or request.link.size != @sizeOf(a.NetworkLinkInfo) or request.link.reserved != 0 or request.link.flags & ~@as(u32, 15) != 0) return a.network_error_invalid;
    const link = sync(request.link.index) catch |err| return fail(err);
    if (!link.ready) return a.network_error_unsupported_policy;
    if (request.bytes > link.info.mtu + 14) return a.network_error_capacity;
    if (request.link.interface_id != link.info.interface_id or request.link.generation != link.info.generation) return a.network_error_provider_changed;
    var mac: [6]u8 = undefined;
    @memcpy(&mac, request.frame[6..12]);
    if (mac[0] & 1 != 0 or std.mem.allEqual(u8, &mac, 0) or request.frame[12] != 0x86 or request.frame[13] != 0xdd) return a.network_error_invalid;
    var destination: w.Address = undefined;
    @memcpy(&destination, request.frame[38..54]);
    if (!link.state.accepts(destination, link.last_ns)) return a.network_error_not_found;
    if (w.multicast(destination)) {
        if (!std.mem.eql(u8, request.frame[0..6], &multicastMac(destination))) return a.network_error_invalid;
    } else if (!std.mem.eql(u8, request.frame[0..6], &link.info.mac)) return a.network_error_invalid;
    var reject: w.Reject = .{};
    const packet = w.parse(&reassembly, link.info.interface_id, link.info.generation, link.info.clock.generation, link.last_ns, request.frame[14..request.bytes], &reject) catch |err| {
        if (err == error.Pending) return 0;
        link.dropped +|= 1;
        if (err == error.ParameterProblem) parameterProblem(link, request.frame[14..request.bytes], reject, mac);
        return fail(err);
    };
    link.rx +|= 1;
    if (packet.next == 59) return 0;
    const code = checksum(&packet);
    if (code != 0) return code;
    if (packet.next == 58 and packet.length != 0 and packet.payload[0] >= 133 and packet.payload[0] <= 137) return ndReceive(link, &packet, mac);
    if (w.zero(packet.source) or !w.multicast(packet.destination) and !link.state.owns(packet.destination, link.last_ns, false)) return a.network_error_invalid;
    if (packet.next == 58 and packet.payload[0] == 128) {
        const source = if (w.multicast(packet.destination)) link.state.selectSource(packet.source, link.last_ns) catch |err| return fail(err) else packet.destination;
        var reply: a.Icmpv6Message = .{};
        const result = icmp(link, a.icmpv6_op_echo_reply, packet.source, packet.destination, packet.payload[0..packet.length], source, &reply);
        if (result != 0) return result;
        return emit(link, reply.source, reply.destination, 58, 64, reply.payload[0..reply.bytes], mac);
    }
    for (&queue) |*entry| if (!entry.used) {
        if (serial == std.math.maxInt(u64)) return a.network_error_capacity;
        serial += 1;
        entry.* = .{ .used = true, .interface = link.info.interface_id, .generation = link.info.generation, .serial = serial, .packet = packet };
        return 0;
    };
    link.dropped +|= 1;
    return a.network_error_capacity;
}
fn packetOperation(op: u32, input: *const a.ProtocolBuffer, output: *a.ProtocolBuffer) i32 {
    const request = load(a.Ipv6Packet, input) orelse return a.network_error_invalid;
    if (request.reserved != 0 or request.flags != 0 or request.bytes > 1240 or request.next_header != 6 and request.next_header != 17 and request.next_header != 58 or !std.mem.allEqual(u8, request.payload[request.bytes..], 0)) return a.network_error_invalid;
    const link = find(request.source.interface_id, request.generation, request.provider) catch |err| return fail(err);
    if (!link.ready or link.state.failed) return a.network_error_unsupported_policy;
    if (!validAddress(link, request.source) or !validAddress(link, request.destination)) return a.network_error_unsupported_scope;
    const left = common.remaining(Clock{ .info = link.info.clock }, request.deadline) catch |err| return common.code(err);
    if (request.deadline.kind == 1 and left.kind == 0) return a.network_error_timeout;
    if (output.data == null or output.capacity < @sizeOf(a.Ipv6Packet)) return a.network_error_capacity;
    var result = request;
    if (op == a.ipv6_op_receive) {
        if (request.bytes != 0 or !w.zero(request.source.bytes) or !w.zero(request.destination.bytes)) return a.network_error_invalid;
        var selected: ?*Queued = null;
        for (&queue) |*entry| if (entry.used and entry.interface == link.info.interface_id and entry.generation == link.info.generation and entry.packet.next == request.next_header and (selected == null or entry.serial < selected.?.serial)) {
            selected = entry;
        };
        const entry = selected orelse return a.network_error_would_block;
        result.source = networkAddress(link, entry.packet.source);
        result.destination = networkAddress(link, entry.packet.destination);
        result.bytes = @intCast(entry.packet.length);
        result.flags = if (entry.packet.fragmented) a.ipv6_packet_flag_fragmented else 0;
        @memcpy(result.payload[0..entry.packet.length], entry.packet.payload[0..entry.packet.length]);
        const code = store(a.Ipv6Packet, &result, output);
        if (code == 0) entry.* = .{};
        return code;
    }
    if (w.zero(request.destination.bytes)) return a.network_error_invalid;
    if (w.zero(result.source.bytes)) result.source = networkAddress(link, link.state.selectSource(request.destination.bytes, link.last_ns) catch |err| return fail(err));
    if (!link.state.owns(result.source.bytes, link.last_ns, false)) return a.network_error_invalid;
    var packet: w.Packet = .{ .source = result.source.bytes, .destination = result.destination.bytes, .next = @intCast(request.next_header), .length = request.bytes };
    @memcpy(packet.payload[0..packet.length], request.payload[0..packet.length]);
    const validated = checksum(&packet);
    if (validated != 0) return validated;
    const next = link.state.nextHop(packet.destination, link.last_ns) catch |err| return fail(err);
    var mac: [6]u8 = undefined;
    if (w.multicast(next)) mac = multicastMac(next) else {
        var neighbor: a.NdpEvent = .{};
        const code = nd(link, a.ndp_op_resolve, next, 0, &neighbor);
        if (code != 0) return code;
        if (neighbor.kind == a.ndp_action_timed_out) {
            link.state.neighborFailed(neighbor.target, link.last_ns);
            return a.network_error_timeout;
        }
        if (neighbor.kind != a.ndp_action_resolved) {
            if (neighbor.kind == a.ndp_action_multicast_probe or neighbor.kind == a.ndp_action_unicast_probe) {
                const sent = probe(link, neighbor);
                if (sent != 0 and sent != a.network_error_would_block) return sent;
            }
            return a.network_error_would_block;
        }
        mac = neighbor.mac;
    }
    const code = emit(link, packet.source, packet.destination, packet.next, 64, packet.payload[0..packet.length], mac);
    return if (code != 0) code else store(a.Ipv6Packet, &result, output);
}
export fn ipv6_dispatch(op: u32, input: *const a.ProtocolBuffer, output: *a.ProtocolBuffer) callconv(.c) i32 {
    if (api == null) return a.network_error_backend;
    if (input.flags != 0 or input.reserved != 0 or input.len > input.capacity or output.flags != 0 or output.reserved != 0) return a.network_error_invalid;
    if (op == a.ipv6_op_tick) {
        if (input.len != 0 or output.capacity != 0) return a.network_error_invalid;
        for (0..links.len) |i| {
            const link = sync(i) catch continue;
            tick(link);
        }
        output.len = 0;
        return 0;
    }
    if (op == a.ipv6_op_handle_rx) {
        if (output.capacity != 0) return a.network_error_invalid;
        const request = load(a.Ipv6FrameOp, input) orelse return a.network_error_invalid;
        const code = receiveFrame(request);
        if (code == 0) output.len = 0;
        return code;
    }
    if (op == a.ipv6_op_send or op == a.ipv6_op_receive) return packetOperation(op, input, output);
    if (op == a.ipv6_op_configure) {
        const request = load(a.Ipv6AddressConfig, input) orelse return a.network_error_invalid;
        if (output.data == null or output.capacity < @sizeOf(a.Ipv6InterfaceInfo)) return a.network_error_capacity;
        if (request.reserved != 0 or request.flags > 1 or request.address.interface_id != request.interface_id) return a.network_error_invalid;
        const link = find(request.interface_id, request.generation, request.provider) catch |err| return fail(err);
        if (!link.ready or link.state.failed) return a.network_error_unsupported_policy;
        if (!validAddress(link, request.address) or w.linkLocal(request.address.bytes)) return a.network_error_unsupported_scope;
        var candidate = link.state;
        if (request.flags == 1) {
            if (request.preferred_lifetime_ns != 0 or request.valid_lifetime_ns != 0 or request.prefix_length != 0) return a.network_error_invalid;
            candidate.remove(request.address.bytes) catch |err| return fail(err);
        } else {
            _ = candidate.add(request.address.bytes, request.prefix_length, address.manual, link.last_ns, request.preferred_lifetime_ns, request.valid_lifetime_ns, nonce() catch return a.network_error_backend) catch |err| return fail(err);
            candidate.manualPrefix(request.address.bytes, request.prefix_length, tryExpires(link.last_ns, request.valid_lifetime_ns) orelse return a.network_error_invalid) catch |err| return fail(err);
        }
        link.state = candidate;
        const result = interfaceInfo(link);
        return store(a.Ipv6InterfaceInfo, &result, output);
    }
    if (op != a.ipv6_op_info and op != a.ipv6_op_address and op != a.ipv6_op_route) return a.network_error_unsupported_policy;
    const request = load(a.Ipv6InterfaceQuery, input) orelse return a.network_error_invalid;
    if (request.reserved != 0 or op == a.ipv6_op_info and request.cursor != 0) return a.network_error_invalid;
    const link = sync(request.index) catch |err| return fail(err);
    if (request.provider != 0 and request.provider != link.info.provider or request.interface_id != 0 and request.interface_id != link.info.interface_id or request.generation != 0 and request.generation != link.info.generation) return a.network_error_provider_changed;
    if (op == a.ipv6_op_info) {
        const result = interfaceInfo(link);
        return store(a.Ipv6InterfaceInfo, &result, output);
    }
    if (request.provider == 0 or request.interface_id == 0 or request.generation == 0) return a.network_error_invalid;
    var cursor: u32 = 0;
    if (op == a.ipv6_op_address) for (link.state.addresses) |row| {
        if (!row.used) continue;
        if (cursor == request.cursor) {
            const result: a.Ipv6AddressInfo = .{ .address = networkAddress(link, row.ip), .provider = link.info.provider, .generation = link.info.generation, .preferred_until_ns = row.preferred_until, .valid_until_ns = row.valid_until, .flags = row.flags, .prefix_length = row.bits };
            return store(a.Ipv6AddressInfo, &result, output);
        }
        cursor += 1;
    } else for (link.state.routes) |row| {
        if (!row.used) continue;
        if (cursor == request.cursor) {
            const result: a.Ipv6RouteInfo = .{ .prefix = networkAddress(link, row.prefix), .gateway = networkAddress(link, row.gateway), .provider = link.info.provider, .generation = link.info.generation, .valid_until_ns = row.valid_until, .prefix_length = row.bits, .flags = row.flags };
            return store(a.Ipv6RouteInfo, &result, output);
        }
        cursor += 1;
    };
    return a.network_error_not_found;
}
fn tryExpires(now: u64, duration: u64) ?u64 {
    return address.expires(now, duration) catch null;
}
