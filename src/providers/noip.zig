const std = @import("std");
const config = @import("../config.zig");

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    _ = allocator;
    std.log.info("No-IP: {s} → {s} (待实现)", .{ entry.domain, ip });
    return true;
}
