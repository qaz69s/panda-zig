const std = @import("std");
const config = @import("../config.zig");
const http = @import("../http.zig");

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    const token = entry.token;
    const domain = entry.domain;
    if (token.len == 0) { std.debug.print("DuckDNS: 缺少令牌\\n", .{}); return false; }
    if (domain.len == 0) { std.debug.print("DuckDNS: 缺少域名\\n", .{}); return false; }

    const url = std.fmt.allocPrint(allocator, "https://www.duckdns.org/update?domains={s}&token={s}&ip={s}", .{ domain, token, ip }) catch {
        std.debug.print("DuckDNS: 内存不足\\n", .{}); return false;
    };
    defer allocator.free(url);

    const body = http.get(allocator, url, &.{}) catch |e| {
        std.debug.print("DuckDNS: 更新失败: {s}\\n", .{@errorName(e)});
        return false;
    };
    defer allocator.free(body);

    const trimmed = std.mem.trim(u8, body, " \n\r\t");
    if (std.mem.eql(u8, trimmed, "OK")) {
        std.debug.print("DuckDNS: {s} -> {s}\\n", .{ domain, ip });
        return true;
    }

    std.debug.print("DuckDNS: 错误: {s}\\n", .{trimmed});
    return false;
}
