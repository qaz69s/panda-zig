const std = @import("std");
const config = @import("../config.zig");
const http = @import("../http.zig");

// Simple JSON field extractor for DNSPod responses
fn extractStr(allocator: std.mem.Allocator, json: []const u8, field: []const u8) ![]const u8 {
    const needle = try std.fmt.allocPrint(allocator, "\"{s}\":\"", .{field});
    defer allocator.free(needle);
    const start = std.mem.indexOf(u8, json, needle) orelse return "";
    const val_start = start + needle.len;
    const val_end = std.mem.indexOfScalarPos(u8, json, val_start, '"') orelse return "";
    return try allocator.dupe(u8, json[val_start..val_end]);
}

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    const token = entry.token;
    const domain = entry.domain;
    const ttl = entry.ttl;
    const record_type = if (std.ascii.eqlIgnoreCase(entry.record_type, "BOTH")) "A" else entry.record_type;

    if (token.len == 0) { std.debug.print("DNSPod: 缺少令牌\\n", .{}); return false; }
    if (domain.len == 0) { std.debug.print("DNSPod: 缺少域名\\n", .{}); return false; }

    // Split domain into subdomain + root
    const dot = std.mem.indexOfScalar(u8, domain, '.') orelse {
        std.debug.print("DNSPod: 域名格式错误: {s}\\n", .{domain});
        return false;
    };
    const subdomain = domain[0..dot];
    const root_domain = domain[dot + 1 ..];

    const headers = [_]http.Header{
        .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
    };

    // Step 1: Search for existing records
    const search_body = std.fmt.allocPrint(allocator,
        "login_token={s}&format=json&domain={s}&sub_domain={s}&record_type={s}",
        .{ token, root_domain, subdomain, record_type }
    ) catch {
        std.debug.print("DNSPod: 内存不足\\n", .{}); return false;
    };
    defer allocator.free(search_body);

    const search_resp = http.post(allocator, "https://dnsapi.cn/Record.List", search_body,
        "application/x-www-form-urlencoded", &headers) catch |e| {
        std.debug.print("DNSPod: 查询记录失败: {s}\\n", .{@errorName(e)});
        return false;
    };
    defer allocator.free(search_resp);

    const status_code = extractStr(allocator, search_resp, "code") catch "";
    defer allocator.free(status_code);

    // Check if record exists and get its ID
    var record_id: ?[]const u8 = null;
    if (std.mem.eql(u8, status_code, "1")) {
        // Find first record id
        const rid = extractStr(allocator, search_resp, "id") catch "";
        if (rid.len > 0) {
            record_id = rid;
        } else {
            allocator.free(rid);
        }
    }

    // Step 2: Create or update the record
    const action = if (record_id != null) "Record.Modify" else "Record.Create";
    const verb = if (record_id != null) "更新" else "创建";

    const update_body_str = if (record_id != null) blk: {
        const s = std.fmt.allocPrint(allocator,
            "login_token={s}&format=json&domain={s}&sub_domain={s}&record_type={s}&value={s}&ttl={d}&record_line=默认&record_id={s}",
            .{ token, root_domain, subdomain, record_type, ip, ttl, record_id.? }
        ) catch { return false; };
        break :blk s;
    } else blk: {
        const s = std.fmt.allocPrint(allocator,
            "login_token={s}&format=json&domain={s}&sub_domain={s}&record_type={s}&value={s}&ttl={d}&record_line=默认",
            .{ token, root_domain, subdomain, record_type, ip, ttl }
        ) catch { return false; };
        break :blk s;
    };
    defer allocator.free(update_body_str);
    if (record_id) |rid| allocator.free(rid);

    const url = std.fmt.allocPrint(allocator, "https://dnsapi.cn/{s}", .{action}) catch {
        std.debug.print("DNSPod: 内存不足\\n", .{}); return false;
    };
    defer allocator.free(url);

    const update_resp = http.post(allocator, url, update_body_str,
        "application/x-www-form-urlencoded", &headers) catch |e| {
        std.debug.print("DNSPod: {s}记录失败: {s}\\n", .{ verb, @errorName(e) });
        return false;
    };
    defer allocator.free(update_resp);

    const result_code = extractStr(allocator, update_resp, "code") catch "";
    defer allocator.free(result_code);

    if (std.mem.eql(u8, result_code, "1")) {
        std.debug.print("DNSPod: {s} {s} -> {s}\\n", .{ verb, domain, ip });
        return true;
    }

    std.debug.print("DNSPod: {s}失败: {s}\\n", .{ verb, update_resp });
    return false;
}
