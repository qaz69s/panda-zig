const std = @import("std");
const http = @import("http.zig");

/// Detect public IP by trying each URL in order
pub fn detectIP(urls: []const []const u8, allocator: std.mem.Allocator) !?[]const u8 {
    for (urls) |url| {
        const result = http.get(allocator, url, &.{}) catch |e| {
            std.debug.print("IP 检测: {s} 失败: {s}\n", .{ url, @errorName(e) });
            continue;
        };
        defer allocator.free(result);

        // Extract IPv4 address from the response
        if (extractIP(result, allocator)) |ip| return ip;
    }
    return null;
}

/// Detect IP from a network interface
/// Uses SIOCGIFADDR ioctl for IPv4 and /proc/net/if_inet6 for IPv6
pub fn detectIPFromIface(ifname: []const u8, allocator: std.mem.Allocator, is_v6: bool) !?[]const u8 {
    if (ifname.len == 0) return null;

    if (is_v6) {
        return detectIPv6FromIface(ifname, allocator);
    }
    return detectIPv4FromIface(ifname, allocator);
}

/// Get IPv4 address of a network interface via SIOCGIFADDR ioctl
fn detectIPv4FromIface(ifname: []const u8, allocator: std.mem.Allocator) !?[]const u8 {
    const sock = try std.posix.socket(std.os.linux.AF.INET, std.os.linux.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    var ifr: std.os.linux.ifreq = std.mem.zeroes(std.os.linux.ifreq);

    // Copy interface name, ensure null-terminated
    const name_len = @min(ifname.len, std.os.linux.IFNAMESIZE - 1);
    @memcpy(ifr.ifrn.name[0..name_len], ifname[0..name_len]);

    _ = std.os.linux.ioctl(sock, std.os.linux.SIOCGIFADDR, @intFromPtr(&ifr));

    // Extract IPv4 address from sockaddr_in
    const addr_in = @as(*const std.os.linux.sockaddr.in, @alignCast(@ptrCast(&ifr.ifru.addr)));
    const ip_raw = addr_in.addr;

    // Convert to dotted decimal string
    const bytes: [4]u8 = @bitCast(@byteSwap(ip_raw));
    const ip_str = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
        bytes[0], bytes[1], bytes[2], bytes[3],
    });

    std.debug.print("网卡 {s} IPv4: {s}\n", .{ ifname, ip_str });
    return ip_str;
}

/// Get IPv6 global unicast address of a network interface from /proc/net/if_inet6
fn detectIPv6FromIface(ifname: []const u8, allocator: std.mem.Allocator) !?[]const u8 {
    const file = std.fs.cwd().openFile("/proc/net/if_inet6", .{}) catch |e| {
        std.debug.print("无法读取 /proc/net/if_inet6: {s}\n", .{@errorName(e)});
        return null;
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 4096);
    defer allocator.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;

        // Format: %32x %02x %02x %02x %02x %s
        // addr(32hex) idx prefix_len scope flags ifname
        var fields = std.mem.splitScalar(u8, trimmed, ' ');
        const hex_addr = fields.next() orelse continue;
        _ = fields.next() orelse continue; // interface index
        _ = fields.next() orelse continue; // prefix length
        const scope_str = fields.next() orelse continue; // scope (0x20 = global)
        _ = fields.next() orelse continue; // flags
        const name = fields.next() orelse continue;

        const scope = std.fmt.parseInt(u8, scope_str, 16) catch 0;

        // Only match global unicast (scope 0x00) interfaces
        if (!std.mem.eql(u8, name, ifname)) continue;
        if (scope != 0x00) continue;

        if (hex_addr.len != 32) continue;

        // Format the 32 hex digits into proper IPv6 with colons
        var ip_str_buf: [45]u8 = undefined;
        var buf_idx: usize = 0;
        var i: usize = 0;
        while (i < 32) : (i += 4) {
            if (buf_idx > 0) {
                ip_str_buf[buf_idx] = ':';
                buf_idx += 1;
            }
            @memcpy(ip_str_buf[buf_idx..buf_idx+4], hex_addr[i .. i + 4]);
            buf_idx += 4;
        }

        // Simplify: remove leading zeros in each group
        var groups = std.mem.splitSequence(u8, ip_str_buf[0..buf_idx], ":");
        var simplified = std.ArrayList(u8).init(allocator);
        defer simplified.deinit();
        var group_count: usize = 0;
        while (groups.next()) |group| {
            if (group_count > 0) {
                try simplified.append(':');
            }
            // Strip leading zeros but keep at least one digit
            var trimmed_group = group;
            while (trimmed_group.len > 1 and trimmed_group[0] == '0') {
                trimmed_group = trimmed_group[1..];
            }
            try simplified.appendSlice(trimmed_group);
            group_count += 1;
        }

        const ip = try simplified.toOwnedSlice();
        std.debug.print("网卡 {s} IPv6: {s}\n", .{ ifname, ip });
        return ip;
    }

    std.debug.print("网卡 {s} 未找到全局 IPv6 地址\n", .{ifname});
    return null;
}

/// Extract a valid IP address (IPv4 or IPv6) from a text response
fn extractIP(text: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
    // Try to find an IPv4 address: xxx.xxx.xxx.xxx
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (std.ascii.isDigit(c) or c == ':') {
            var end = i;
            while (end < text.len) : (end += 1) {
                const ch = text[end];
                if (!std.ascii.isAlphanumeric(ch) and ch != '.' and ch != ':') break;
            }
            const candidate = std.mem.trim(u8, text[i..end], " \t\r\n.:");
            if (candidate.len > 0) {
                // Check if it looks like an IP (has dot for IPv4 or colon for IPv6)
                var has_dot = false;
                var has_colon = false;
                var is_good = true;
                for (candidate) |ch| {
                    if (ch == '.') has_dot = true;
                    if (ch == ':') has_colon = true;
                    if (ch == '<' or ch == '>') is_good = false;
                }
                if ((has_dot or has_colon) and is_good) {
                    const ip = allocator.dupe(u8, candidate) catch continue;
                    // Verify it's a reasonable IP format
                    if (has_dot) {
                        // IPv4: should have exactly 3 dots
                        var dot_count: usize = 0;
                        for (ip) |ch| {
                            if (ch == '.') dot_count += 1;
                        }
                        if (dot_count == 3) return ip;
                    } else {
                        // IPv6: should have at least 2 colons
                        var colon_count: usize = 0;
                        for (ip) |ch| {
                            if (ch == ':') colon_count += 1;
                        }
                        if (colon_count >= 2) return ip;
                    }
                    allocator.free(ip);
                }
            }
            i = end;
        }
    }
    return null;
}
