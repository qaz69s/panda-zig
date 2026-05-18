const std = @import("std");

pub const State = struct {
    // Maps "name_recordType" -> ip
    entries: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,
    dirty: bool,

    pub fn init(allocator: std.mem.Allocator) State {
        return .{
            .entries = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
            .dirty = false,
        };
    }

    pub fn deinit(self: *State) void {
        var iter = self.entries.iterator();
        while (iter.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            self.allocator.free(kv.value_ptr.*);
        }
        self.entries.deinit();
    }

    pub fn isUnchanged(self: *State, key: []const u8, ip: []const u8) bool {
        if (self.entries.get(key)) |last_ip| {
            return std.mem.eql(u8, last_ip, ip);
        }
        return false;
    }

    pub fn save(self: *State, key: []const u8, ip: []const u8) !void {
        // Remove old entry if exists
        if (self.entries.fetchRemove(key)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }
        const k = try self.allocator.dupe(u8, key);
        const v = try self.allocator.dupe(u8, ip);
        try self.entries.put(k, v);
        self.dirty = true;
    }
};

pub fn entryFingerprint(provider: []const u8, domain: []const u8, record_type: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}|{s}|{s}", .{ provider, domain, record_type });
}
