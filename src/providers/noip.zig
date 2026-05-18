const std = @import("std");
const config = @import("../config.zig");
const http = @import("../http.zig");

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    const token = entry.token;
    const domain = entry.domain;
    if (token.len == 0) { std.debug.print("No-IP: 缺少令牌\\n", .{}); return false; }
    if (domain.len == 0) { std.debug.print("No-IP: 缺少域名\\n", .{}); return false; }

    // No-IP uses Basic Auth with username:password as token
    const base64_encoder = std.base64.standard.Encoder;
    const encoded_len = base64_encoder.calcSize(token.len);
    const encoded_buf = allocator.alloc(u8, encoded_len) catch {
        std.debug.print("No-IP: 内存不足\\n", .{});
        return false;
    };
    const encoded = base64_encoder.encode(encoded_buf, token);

    const url = std.fmt.allocPrint(allocator, "https://dynupdate.no-ip.com/nic/update?hostname={s}&myip={s}", .{ domain, ip }) catch {
        std.debug.print("No-IP: 内存不足\\n", .{}); return false;
    };
    defer allocator.free(url);

    const auth = std.fmt.allocPrint(allocator, "Basic {s}", .{encoded}) catch {
        std.debug.print("No-IP: 内存不足\\n", .{}); return false;
    };
    defer allocator.free(auth);

    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = auth },
        .{ .name = "User-Agent", .value = "Panda DDNS/1.0" },
    };

    const body = http.get(allocator, url, &headers) catch |e| {
        std.debug.print("No-IP: 更新失败: {s}\\n", .{@errorName(e)});
        return false;
    };
    defer allocator.free(body);

    const trimmed = std.mem.trim(u8, body, " \n\r\t");
    if (std.mem.startsWith(u8, trimmed, "good") or std.mem.startsWith(u8, trimmed, "nochg")) {
        std.debug.print("No-IP: {s} -> {s} ({s})\\n", .{ domain, ip, trimmed });
        return true;
    }

    std.debug.print("No-IP: 错误: {s}\\n", .{trimmed});
    return false;
}
