const std = @import("std");

pub fn detectIP(urls: []const []const u8, allocator: std.mem.Allocator) !?[]const u8 {
    for (urls) |url| {
        const result = try fetchURL(allocator, url, 10000);
        defer allocator.free(result);

        if (std.mem.trim(u8, result, " \t\r\n").len == 0) continue;

        const ip = try allocator.dupe(u8, std.mem.trim(u8, result, " \t\r\n"));

        // Validate it looks like an IP
        var has_dot = false;
        var has_colon = false;
        for (ip) |c| {
            if (c == '.') has_dot = true;
            if (c == ':') has_colon = true;
        }

        // Basic sanity: contains dot (IPv4) or colon (IPv6), no HTML
        if (has_dot or has_colon) {
            // Make sure it's not HTML
            if (std.mem.indexOf(u8, ip, "<") == null and
                std.mem.indexOf(u8, ip, ">") == null)
            {
                return ip;
            }
        }
        allocator.free(ip);
    }
    return null;
}

fn fetchURL(allocator: std.mem.Allocator, url: []const u8, _: u64) ![]const u8 {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var server_header_buffer: [4096]u8 = undefined;

    var req = try client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
    });
    defer req.deinit();

    req.transfer_encoding = .chunked;
    try req.send();

    var body = std.ArrayList(u8).init(allocator);
    defer body.deinit();

    // Use a simple read loop instead of timeout-based approach
    const reader = req.reader();
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = reader.read(&buf) catch |e| {
            if (e == error.EndOfStream) break;
            return e;
        };
        if (n == 0) break;
        body.appendSlice(buf[0..n]) catch {};
    }

    try req.finish();
    if (req.response.status != .ok) {
        return error.HttpNotOk;
    }

    return body.toOwnedSlice();
}
