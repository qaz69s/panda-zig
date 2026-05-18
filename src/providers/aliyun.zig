const std = @import("std");
const config = @import("../config.zig");
const http = @import("../http.zig");

// Simple JSON field extractor for Aliyun responses
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
    const val_start = start + needle.len;
    // Skip whitespace
    var pos = val_start;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t')) pos += 1;
    if (pos >= json.len) return "";
    // Read until comma, brace, or bracket
    const end = std.mem.indexOfAnyPos(u8, json, pos, ",}]\n\r") orelse json.len;
    return try allocator.dupe(u8, json[pos..end]);
}

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    const token = entry.token;
    const domain = entry.domain;
    const ttl = entry.ttl;
    const record_type = if (std.ascii.eqlIgnoreCase(entry.record_type, "BOTH")) "A" else entry.record_type;

    if (token.len == 0) { std.debug.print("阿里云: 缺少令牌\\n", .{}); return false; }
    if (domain.len == 0) { std.debug.print("阿里云: 缺少域名\\n", .{}); return false; }

    // Split domain into subdomain + root
    const dot = std.mem.indexOfScalar(u8, domain, '.') orelse {
        std.debug.print("阿里云: 域名格式错误: {s}\\n", .{domain});
        return false;
    };
    const subdomain = domain[0..dot];
    const root_domain = domain[dot + 1 ..];

    // Step 1: Search for existing records
    const search_url = std.fmt.allocPrint(allocator,
        "https://alidns.aliyuncs.com/?Action=DescribeDomainRecords&DomainName={s}&RRKeyWord={s}&Type={s}&AccessKeyId={s}&Format=JSON&Version=2015-01-09",
        .{ root_domain, subdomain, record_type, token }
    ) catch {
        std.debug.print("阿里云: 内存不足\\n", .{}); return false;
    };
    defer allocator.free(search_url);

    const search_resp = http.get(allocator, search_url, &.{}) catch |e| {
        std.debug.print("阿里云: 查询记录失败: {s}\\n", .{@errorName(e)});
        return false;
    };
    defer allocator.free(search_resp);

    // Check for error code in response
    const err_code = extractStr(allocator, search_resp, "Code") catch "";
    defer allocator.free(err_code);

    if (err_code.len > 0) {
        const err_msg = extractStr(allocator, search_resp, "Message") catch "";
        defer allocator.free(err_msg);
        std.debug.print("阿里云: API 错误: {s} - {s}\\n", .{ err_code, if (err_msg.len > 0) err_msg else "未知" });
        return false;
    }

    // Find record ID
    var record_id: ?[]const u8 = null;
    const found_rid = extractNum(allocator, search_resp, "RecordId") catch "";
    if (found_rid.len > 0) {
        record_id = found_rid;
    } else {
        allocator.free(found_rid);
    }

    // Step 2: Create or update the record
    const action = if (record_id != null) "UpdateDomainRecord" else "AddDomainRecord";
    const verb = if (record_id != null) "更新" else "创建";

    const update_url = if (record_id != null) blk: {
        const s = std.fmt.allocPrint(allocator,
            "https://alidns.aliyuncs.com/?Action={s}&DomainName={s}&RR={s}&Type={s}&Value={s}&TTL={d}&AccessKeyId={s}&Format=JSON&Version=2015-01-09&RecordId={s}",
            .{ action, root_domain, subdomain, record_type, ip, ttl, token, record_id.? }
        ) catch { return false; };
        break :blk s;
    } else blk: {
        const s = std.fmt.allocPrint(allocator,
            "https://alidns.aliyuncs.com/?Action={s}&DomainName={s}&RR={s}&Type={s}&Value={s}&TTL={d}&AccessKeyId={s}&Format=JSON&Version=2015-01-09",
            .{ action, root_domain, subdomain, record_type, ip, ttl, token }
        ) catch { return false; };
        break :blk s;
    };
    defer allocator.free(update_url);
    if (record_id) |rid| allocator.free(rid);

    const update_resp = http.get(allocator, update_url, &.{}) catch |e| {
        std.debug.print("阿里云: {s}记录失败: {s}\\n", .{ verb, @errorName(e) });
        return false;
    };
    defer allocator.free(update_resp);

    const resp_code = extractStr(allocator, update_resp, "Code") catch "";
    defer allocator.free(resp_code);

    if (resp_code.len == 0) {
        std.debug.print("阿里云: {s} {s} -> {s}\\n", .{ verb, domain, ip });
        return true;
    }

    std.debug.print("阿里云: {s}失败: {s}\\n", .{ verb, update_resp });
    return false;
}
