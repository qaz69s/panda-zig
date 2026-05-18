const std = @import("std");
const config = @import("../config.zig");
const http = @import("../http.zig");

// Simple JSON field extractor
fn extractStr(allocator: std.mem.Allocator, json: []const u8, field: []const u8) ![]const u8 {
    const needle = try std.fmt.allocPrint(allocator, "\"{s}\":\"", .{field});
    defer allocator.free(needle);
    const start = std.mem.indexOf(u8, json, needle) orelse return "";
    const val_start = start + needle.len;
    const val_end = std.mem.indexOfScalarPos(u8, json, val_start, '"') orelse return "";
    return try allocator.dupe(u8, json[val_start..val_end]);
}

fn extractNum(allocator: std.mem.Allocator, json: []const u8, field: []const u8) ![]const u8 {
    const needle = try std.fmt.allocPrint(allocator, "\"{s}\":", .{field});
    defer allocator.free(needle);
    const start = std.mem.indexOf(u8, json, needle) orelse return "";
    var pos = start + needle.len;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t')) pos += 1;
    if (pos >= json.len) return "";
    const end = std.mem.indexOfAnyPos(u8, json, pos, ",}]\n\r") orelse json.len;
    return try allocator.dupe(u8, json[pos..end]);
}

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    const token = entry.token;
    const domain = entry.domain;
    const ttl = entry.ttl;
    const record_type = if (std.ascii.eqlIgnoreCase(entry.record_type, "BOTH")) "A" else entry.record_type;

    if (token.len == 0) { std.debug.print("百度云: 缺少令牌\\n", .{}); return false; }
    if (domain.len == 0) { std.debug.print("百度云: 缺少域名\\n", .{}); return false; }

    // Split domain into subdomain + root
    const dot = std.mem.indexOfScalar(u8, domain, '.') orelse {
        std.debug.print("百度云: 域名格式错误: {s}\\n", .{domain});
        return false;
    };
    const subdomain = domain[0..dot];
    const root_domain = domain[dot + 1 ..];

    const auth = std.fmt.allocPrint(allocator, "Bearer {s}", .{token}) catch {
        std.debug.print("百度云: 内存不足\\n", .{}); return false;
    };
    defer allocator.free(auth);

    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = auth },
        .{ .name = "Content-Type", .value = "application/json" },
    };

    // Step 1: Search for existing records
    const list_url = std.fmt.allocPrint(allocator,
        "https://dns.baidubce.com/v1/dns/zone/{s}/record?rr={s}&type={s}",
        .{ root_domain, subdomain, record_type }
    ) catch {
        std.debug.print("百度云: 内存不足\\n", .{}); return false;
    };
    defer allocator.free(list_url);

    const list_resp = http.get(allocator, list_url, &headers) catch |e| {
        std.debug.print("百度云: 查询记录失败: {s}\\n", .{@errorName(e)});
        return false;
    };
    defer allocator.free(list_resp);

    // Find record ID
    var record_id: ?[]const u8 = null;
    const found_rid = extractNum(allocator, list_resp, "id") catch "";
    if (found_rid.len > 0) {
        record_id = found_rid;
    } else {
        allocator.free(found_rid);
    }

    // Step 2: Create or update the record
    const verb = if (record_id != null) "更新" else "创建";

    const payload = std.fmt.allocPrint(allocator, "{{\"rr\":\"{s}\",\"type\":\"{s}\",\"value\":\"{s}\",\"ttl\":{d}}}", .{
        subdomain, record_type, ip, ttl,
    }) catch {
        std.debug.print("百度云: 内存不足\\n", .{}); return false;
    };
    defer allocator.free(payload);

    if (record_id) |rid| {
        defer allocator.free(rid);
        const update_url = std.fmt.allocPrint(allocator,
            "https://dns.baidubce.com/v1/dns/zone/{s}/record/{s}",
            .{ root_domain, rid }
        ) catch {
            std.debug.print("百度云: 内存不足\\n", .{}); return false;
        };
        defer allocator.free(update_url);

        const update_resp = http.put(allocator, update_url, payload, &headers) catch |e| {
            std.debug.print("百度云: {s}记录失败: {s}\\n", .{ verb, @errorName(e) });
            return false;
        };
        defer allocator.free(update_resp);
    } else {
        const create_url = std.fmt.allocPrint(allocator,
            "https://dns.baidubce.com/v1/dns/zone/{s}/record",
            .{ root_domain }
        ) catch {
            std.debug.print("百度云: 内存不足\\n", .{}); return false;
        };
        defer allocator.free(create_url);

        const create_resp = http.post(allocator, create_url, payload, "application/json", &headers) catch |e| {
            std.debug.print("百度云: {s}记录失败: {s}\\n", .{ verb, @errorName(e) });
            return false;
        };
        defer allocator.free(create_resp);
    }

    std.debug.print("百度云: {s} {s} -> {s}\\n", .{ verb, domain, ip });
    return true;
}
