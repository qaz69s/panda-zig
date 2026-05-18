const std = @import("std");
const http = @import("http.zig");

pub fn detectIP(urls: []const []const u8, allocator: std.mem.Allocator) !?[]const u8 {
    for (urls) |url| {
        const result = http.get(allocator, url, &.{}) catch |e| {
            std.debug.print("ip_detect: {s} failed: {s}\n", .{ url, @errorName(e) });
            continue;
        };
        defer allocator.free(result);

        // Extract IPv4 address from the response
        if (extractIP(result, allocator)) |ip| return ip;
    }
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
