const std = @import("std");
const config = @import("../config.zig");

pub const cloudflare = @import("cloudflare.zig");
pub const dnspod = @import("dnspod.zig");
pub const aliyun = @import("aliyun.zig");
pub const noip = @import("noip.zig");
pub const duckdns = @import("duckdns.zig");
pub const baidu = @import("baidu.zig");
pub const custom = @import("custom.zig");

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    const provider = entry.provider;

    if (std.ascii.eqlIgnoreCase(provider, "cloudflare")) {
        return cloudflare.update(allocator, entry, ip);
    } else if (std.ascii.eqlIgnoreCase(provider, "dnspod")) {
        return dnspod.update(allocator, entry, ip);
    } else if (std.ascii.eqlIgnoreCase(provider, "aliyun") or std.ascii.eqlIgnoreCase(provider, "huawei")) {
        return aliyun.update(allocator, entry, ip);
    } else if (std.ascii.eqlIgnoreCase(provider, "noip")) {
        return noip.update(allocator, entry, ip);
    } else if (std.ascii.eqlIgnoreCase(provider, "duckdns")) {
        return duckdns.update(allocator, entry, ip);
    } else if (std.ascii.eqlIgnoreCase(provider, "baidu")) {
        return baidu.update(allocator, entry, ip);
    } else if (std.ascii.eqlIgnoreCase(provider, "custom")) {
        return custom.update(allocator, entry, ip);
    } else {
        std.log.err("{s}: 不支持的提供商 {s}", .{ entry.name, provider });
        return false;
    }
}
