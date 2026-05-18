const std = @import("std");
const config = @import("../config.zig");
const http = @import("../http.zig");

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    const custom_url = entry.custom_url;
    const custom_method = entry.custom_method;
    const custom_headers_raw = entry.custom_headers;

    if (custom_url.len == 0) {
        std.debug.print("Custom: no URL configured\n", .{});
        return false;
    }

    // Build URL by substituting variables
    var url = std.ArrayList(u8).init(allocator);
    defer url.deinit();

    var remaining = custom_url;
    while (std.mem.indexOf(u8, remaining, "{{")) |brace_start| {
        url.appendSlice(remaining[0..brace_start]) catch {
            std.debug.print("Custom: OOM\n", .{});
            return false;
        };
        const brace_end = std.mem.indexOfScalarPos(u8, remaining, brace_start + 2, '}') orelse {
            url.appendSlice(remaining[brace_start..]) catch {};
            break;
        };
        const var_name = remaining[brace_start + 2 .. brace_end];
        const replacement = if (std.mem.eql(u8, var_name, "domain")) entry.domain
            else if (std.mem.eql(u8, var_name, "ip")) ip
            else if (std.mem.eql(u8, var_name, "token")) entry.token
            else if (std.mem.eql(u8, var_name, "type")) entry.record_type
            else remaining[brace_start .. brace_end + 2];
        url.appendSlice(replacement) catch {
            std.debug.print("Custom: OOM\n", .{});
            return false;
        };
        remaining = remaining[brace_end + 2 ..];
    }
    url.appendSlice(remaining) catch {
        std.debug.print("Custom: OOM\n", .{});
        return false;
    };

    // Parse custom headers (JSON object)
    var headers_list = std.ArrayList(http.Header).init(allocator);
    defer headers_list.deinit();

    if (custom_headers_raw.len > 2) {
        var h_remaining = custom_headers_raw;
        if (h_remaining[0] == '{') h_remaining = h_remaining[1..];
        if (h_remaining.len > 0 and h_remaining[h_remaining.len - 1] == '}') h_remaining = h_remaining[0 .. h_remaining.len - 1];

        var h_iter = std.mem.splitScalar(u8, h_remaining, ',');
        while (h_iter.next()) |pair| {
            const colon = std.mem.indexOfScalar(u8, pair, ':') orelse continue;
            const k = std.mem.trim(u8, pair[0..colon], " \"\t");
            const v = std.mem.trim(u8, pair[colon + 1 ..], " \"\t");
            if (k.len > 0 and v.len > 0) {
                headers_list.append(.{ .name = k, .value = v }) catch {};
            }
        }
    }

    const method: std.http.Method = if (std.ascii.eqlIgnoreCase(custom_method, "POST")) .POST else .GET;

    if (method == .GET) {
        _ = http.get(allocator, url.items, headers_list.items) catch |e| {
            std.debug.print("Custom GET: {s} -> {s} failed: {s}\n", .{ entry.domain, ip, @errorName(e) });
            return false;
        };
    } else {
        _ = http.put(allocator, url.items, ip, headers_list.items) catch |e| {
            std.debug.print("Custom POST: {s} -> {s} failed: {s}\n", .{ entry.domain, ip, @errorName(e) });
            return false;
        };
    }

    std.debug.print("Custom: {s} -> {s}\n", .{ entry.domain, ip });
    return true;
}
