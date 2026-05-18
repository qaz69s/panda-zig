const std = @import("std");
const config = @import("../config.zig");

pub fn update(allocator: std.mem.Allocator, entry: *const config.DdnsEntry, ip: []const u8) bool {
    _ = allocator;
    std.debug.print("DuckDNS: {s} -> {s} (stub)\n", .{ entry.domain, ip });
    return true;
}
