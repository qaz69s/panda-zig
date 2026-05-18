const std = @import("std");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

fn defaultCaBundle(allocator: std.mem.Allocator) std.crypto.Certificate.Bundle {
    var bundle = std.crypto.Certificate.Bundle{};
    _ = std.crypto.Certificate.Bundle.addCertsFromFilePath(
        &bundle, allocator, std.fs.cwd(), "/etc/ssl/certs/ca-certificates.crt",
    ) catch {
        _ = std.crypto.Certificate.Bundle.addCertsFromFilePath(
            &bundle, allocator, std.fs.cwd(), "/etc/ssl/cert.pem",
        ) catch {};
    };
    return bundle;
}

/// Simple HTTP GET, reads response body
pub fn get(allocator: std.mem.Allocator, url: []const u8, extra_headers: []const Header) ![]const u8 {
    var client: std.http.Client = .{
        .allocator = allocator,
        .ca_bundle = defaultCaBundle(allocator),
    };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var header_buffer: [4096]u8 = undefined;

    var req = try client.open(.GET, uri, .{ .server_header_buffer = &header_buffer });
    defer req.deinit();

    applyHeaders(&req, extra_headers);

    try req.send();
    try req.finish();
    try req.wait();

    if (req.response.status.class() != .success) return error.HttpNotOk;

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
    return body.toOwnedSlice();
}

/// HTTP POST with form/JSON body, reads response body
pub fn post(allocator: std.mem.Allocator, url: []const u8, body_str: []const u8, content_type: []const u8, extra_headers: []const Header) ![]const u8 {
    var client: std.http.Client = .{
        .allocator = allocator,
        .ca_bundle = defaultCaBundle(allocator),
    };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var header_buffer: [4096]u8 = undefined;

    var req = try client.open(.POST, uri, .{ .server_header_buffer = &header_buffer });
    defer req.deinit();

    applyHeaders(&req, extra_headers);
    if (content_type.len > 0) {
        req.headers.content_type = .{ .override = content_type };
    }

    req.transfer_encoding = .{ .content_length = body_str.len };
    try req.send();
    if (body_str.len > 0) try req.writer().writeAll(body_str);
    try req.finish();
    try req.wait();

    var resp_body = std.ArrayList(u8).init(allocator);
    defer resp_body.deinit();
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = req.read(buf[0..]) catch |e| {
            if (e == error.EndOfStream) break;
            return e;
        };
        if (n == 0) break;
        try resp_body.appendSlice(buf[0..n]);
    }

    return resp_body.toOwnedSlice();
}

/// HTTP PUT with JSON body, reads response body
pub fn put(allocator: std.mem.Allocator, url: []const u8, body_str: []const u8, extra_headers: []const Header) ![]const u8 {
    var client: std.http.Client = .{
        .allocator = allocator,
        .ca_bundle = defaultCaBundle(allocator),
    };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var header_buffer: [4096]u8 = undefined;

    var req = try client.open(.PUT, uri, .{ .server_header_buffer = &header_buffer });
    defer req.deinit();

    applyHeaders(&req, extra_headers);

    // Set transfer encoding for body
    req.transfer_encoding = .{ .content_length = body_str.len };
    try req.send();
    if (body_str.len > 0) try req.writer().writeAll(body_str);
    try req.finish();
    try req.wait();

    // Read response body regardless of status
    var resp_body = std.ArrayList(u8).init(allocator);
    defer resp_body.deinit();
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = req.read(buf[0..]) catch |e| {
            if (e == error.EndOfStream) break;
            return e;
        };
        if (n == 0) break;
        try resp_body.appendSlice(buf[0..n]);
    }

    if (req.response.status.class() != .success) return error.HttpNotOk;

    return resp_body.toOwnedSlice();
}

fn applyHeaders(req: *std.http.Client.Request, headers: []const Header) void {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "authorization")) {
            req.headers.authorization = .{ .override = h.value };
        } else if (std.ascii.eqlIgnoreCase(h.name, "content-type")) {
            req.headers.content_type = .{ .override = h.value };
        } else if (std.ascii.eqlIgnoreCase(h.name, "user-agent")) {
            req.headers.user_agent = .{ .override = h.value };
        }
    }
}
