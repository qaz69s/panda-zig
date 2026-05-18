const std = @import("std");
const config = @import("../config.zig");
const http = @import("../http.zig");

const CF_API = "https://api.cloudflare.com/client/v4";

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    const token = entry.token;
    const domain = entry.domain;
    const zone_id = entry.cf_zone_id;
    const record_type = if (std.ascii.eqlIgnoreCase(entry.record_type, "BOTH")) "A" else entry.record_type;

    if (token.len == 0) { std.debug.print("Cloudflare: token missing\n", .{}); return false; }
    if (domain.len == 0) { std.debug.print("Cloudflare: domain missing\n", .{}); return false; }
    if (zone_id.len == 0) { std.debug.print("Cloudflare: zone_id missing\n", .{}); return false; }

    // Build auth token string
    const bearer = std.fmt.allocPrint(allocator, "Bearer {s}", .{token}) catch {
        std.debug.print("Cloudflare: OOM\n", .{});
        return false;
    };
    defer allocator.free(bearer);

    // Step 1: List DNS records to find record ID
    const list_url = std.fmt.allocPrint(allocator, "{s}/zones/{s}/dns_records?name={s}&type={s}", .{ CF_API, zone_id, domain, record_type }) catch {
        std.debug.print("Cloudflare: OOM\n", .{});
        return false;
    };
    defer allocator.free(list_url);

    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = bearer },
        .{ .name = "Content-Type", .value = "application/json" },
    };

    const list_body = http.get(allocator, list_url, &headers) catch |e| {
        std.debug.print("Cloudflare: failed to list DNS records: {s}\n", .{@errorName(e)});
        return false;
    };
    defer allocator.free(list_body);

    const record_id = extractRecordId(allocator, list_body) catch |e| {
        std.debug.print("Cloudflare: failed to parse DNS record list: {s}\n", .{@errorName(e)});
        std.debug.print("Response: {s}\n", .{list_body});
        return false;
    };
    defer allocator.free(record_id);

    if (record_id.len == 0) {
        std.debug.print("Cloudflare: no existing DNS record found for {s} ({s})\n", .{ domain, record_type });
        return false;
    }

    // Step 2: Update DNS record
    const update_url = std.fmt.allocPrint(allocator, "{s}/zones/{s}/dns_records/{s}", .{ CF_API, zone_id, record_id }) catch {
        std.debug.print("Cloudflare: OOM\n", .{});
        return false;
    };
    defer allocator.free(update_url);

    const update_body = std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"name\":\"{s}\",\"content\":\"{s}\",\"ttl\":{d},\"proxied\":{s}}}", .{
        record_type, domain, ip, entry.ttl, if (entry.cf_proxied) "true" else "false",
    }) catch {
        std.debug.print("Cloudflare: OOM\n", .{});
        return false;
    };
    defer allocator.free(update_body);

    const update_resp = http.put(allocator, update_url, update_body, &headers) catch |e| {
        std.debug.print("Cloudflare: failed to update DNS record: {s}\n", .{@errorName(e)});
        return false;
    };
    defer allocator.free(update_resp);

    std.debug.print("Cloudflare: {s} ({s}) -> {s}\n", .{ domain, record_type, ip });
    return true;
}

fn extractRecordId(allocator: std.mem.Allocator, json_body: []const u8) ![]const u8 {
    const needle = "\"id\":\"";
    const id_start = std.mem.indexOf(u8, json_body, needle) orelse return "";
    const val_start = id_start + needle.len;
    const val_end = std.mem.indexOfScalarPos(u8, json_body, val_start, '"') orelse return "";
    return try allocator.dupe(u8, json_body[val_start..val_end]);
}
