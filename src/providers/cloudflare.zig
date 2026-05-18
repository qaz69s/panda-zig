const std = @import("std");
const config = @import("../config.zig");
const http = @import("../http.zig");

const CF_API = "https://api.cloudflare.com/client/v4";

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    const token = entry.token;
    const domain = entry.domain;
    const record_type = if (std.ascii.eqlIgnoreCase(entry.record_type, "BOTH")) "A" else entry.record_type;

    if (token.len == 0) { std.debug.print("Cloudflare: token missing\n", .{}); return false; }
    if (domain.len == 0) { std.debug.print("Cloudflare: domain missing\n", .{}); return false; }

    const bearer = std.fmt.allocPrint(allocator, "Bearer {s}", .{token}) catch {
        std.debug.print("Cloudflare: OOM\n", .{}); return false;
    };
    defer allocator.free(bearer);

    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = bearer },
        .{ .name = "Content-Type", .value = "application/json" },
    };

    // Step 0: Auto-detect zone ID if not provided
    const zone_id = if (entry.cf_zone_id.len > 0)
        entry.cf_zone_id
    else blk: {
        const zone = autoDetectZone(allocator, domain, &headers) catch |e| {
            std.debug.print("Cloudflare: auto-detect zone failed: {s}\n", .{@errorName(e)});
            return false;
        };
        break :blk zone;
    };
    defer if (entry.cf_zone_id.len == 0) allocator.free(zone_id);

    // Step 1: Find DNS record ID
    const list_url = std.fmt.allocPrint(allocator, "{s}/zones/{s}/dns_records?name={s}&type={s}", .{ CF_API, zone_id, domain, record_type }) catch {
        std.debug.print("Cloudflare: OOM\n", .{}); return false;
    };
    defer allocator.free(list_url);

    const list_body = http.get(allocator, list_url, &headers) catch |e| {
        std.debug.print("Cloudflare: failed to list DNS records: {s}\n", .{@errorName(e)});
        return false;
    };
    defer allocator.free(list_body);

    const record_id = extractField(allocator, list_body, "id") catch |e| {
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
        std.debug.print("Cloudflare: OOM\n", .{}); return false;
    };
    defer allocator.free(update_url);

    const update_body = std.fmt.allocPrint(allocator, "{{\"type\":\"{s}\",\"name\":\"{s}\",\"content\":\"{s}\",\"ttl\":{d},\"proxied\":{s}}}", .{
        record_type, domain, ip, entry.ttl, if (entry.cf_proxied) "true" else "false",
    }) catch {
        std.debug.print("Cloudflare: OOM\n", .{}); return false;
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

/// Auto-detect Cloudflare Zone ID from domain name
fn autoDetectZone(allocator: std.mem.Allocator, domain: []const u8, headers: []const http.Header) ![]const u8 {
    // Extract the zone name (top 2 labels: example.com)
    var zone_name = domain;
    // Try progressively shorter zones: sub.example.com -> example.com
    while (true) {
        const url = try std.fmt.allocPrint(allocator, "{s}/zones?name={s}", .{ CF_API, zone_name });
        defer allocator.free(url);

        const body = try http.get(allocator, url, headers);
        defer allocator.free(body);

        const found_id = try extractField(allocator, body, "id");
        if (found_id.len > 0) return found_id;
        allocator.free(found_id);

        // Try parent domain
        const dot = std.mem.indexOfScalar(u8, zone_name, '.');
        if (dot == null) break;
        zone_name = zone_name[dot.? + 1 ..];
        if (std.mem.count(u8, zone_name, ".") == 0) break;
    }
    return error.ZoneNotFound;
}

/// Extract a JSON field value: "fieldName":"value"
fn extractField(allocator: std.mem.Allocator, json: []const u8, field: []const u8) ![]const u8 {
    const needle = try std.fmt.allocPrint(allocator, "\"{s}\":\"", .{field});
    defer allocator.free(needle);
    const start = std.mem.indexOf(u8, json, needle) orelse return "";
    const val_start = start + needle.len;
    const val_end = std.mem.indexOfScalarPos(u8, json, val_start, '"') orelse return "";
    return try allocator.dupe(u8, json[val_start..val_end]);
}
