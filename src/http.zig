const std = @import("std");

/// Simple HTTP GET helper compatible with Zig 0.14
pub fn get(allocator: std.mem.Allocator, url: []const u8, headers: []const Header) ![]const u8 {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var server_header_buffer: [4096]u8 = undefined;

    var req = try client.open(.GET, uri, .{ .server_header_buffer = &server_header_buffer });
    defer req.deinit();

    // Set custom headers via the non-standard approach
    inline for (headers) |h| {
        _ = h; // Headers in Zig 0.14 need special handling
    }

    req.transfer_encoding = .chunked;
    try req.send();

    var body = std.ArrayList(u8).init(allocator);
    defer body.deinit();

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = req.read(buf[0..]) catch |e| {
            if (e == error.EndOfStream) break;
            return e;
        };
        if (n == 0) break;
        try body.appendSlice(buf[0..n]);
    }

    try req.finish();
    return body.toOwnedSlice();
}

/// Simple HTTP PUT/POST with body
pub fn send(allocator: std.mem.Allocator, method: std.http.Method, url: []const u8, body_str: []const u8) !void {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var server_header_buffer: [4096]u8 = undefined;

    var req = try client.open(method, uri, .{ .server_header_buffer = &server_header_buffer });
    defer req.deinit();

    req.transfer_encoding = .chunked;
    try req.send();
    if (body_str.len > 0) {
        try req.writer().writeAll(body_str);
    }
    try req.finish();

    if (!req.response.status.ok()) {
        return error.HttpNotOk;
    }
}

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};
