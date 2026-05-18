const std = @import("std");

pub const GlobalConfig = struct {
    enabled: bool = true,
    interval: u64 = 300,
};

pub const IpDetectConfig = struct {
    ipv4_urls: std.ArrayList([]const u8),
    ipv6_urls: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator) IpDetectConfig {
        var v4 = std.ArrayList([]const u8).init(allocator);
        var v6 = std.ArrayList([]const u8).init(allocator);
        v4.append("https://ddns.oray.com/checkip") catch {};
        v4.append("https://myip.ipip.net") catch {};
        v4.append("https://ip.3322.net") catch {};
        v4.append("https://4.ipw.cn") catch {};
        v4.append("https://v4.yinghualuo.cn/bejson") catch {};
        v4.append("https://api.ipify.org") catch {};
        v4.append("https://ident.me") catch {};
        v4.append("https://ipinfo.io/ip") catch {};
        v6.append("https://api6.ipify.org") catch {};
        v6.append("https://ipv6.ident.me") catch {};
        v6.append("https://v6.ipinfo.io/ip") catch {};
        return .{ .ipv4_urls = v4, .ipv6_urls = v6 };
    }

    pub fn deinit(self: *IpDetectConfig) void {
        self.ipv4_urls.deinit();
        self.ipv6_urls.deinit();
    }
};

pub const DdnsEntry = struct {
    name: []const u8,
    enabled: bool = true,
    provider: []const u8,
    domain: []const u8,
    record_type: []const u8, // "A", "AAAA", "BOTH"
    token: []const u8,
    ttl: u64 = 120,
    // Provider-specific
    cf_zone_id: []const u8 = "",
    cf_proxied: bool = false,
    custom_url: []const u8 = "",
    custom_method: []const u8 = "GET",
    custom_headers: []const u8 = "{}",
};

pub const PandaConfig = struct {
    global: GlobalConfig,
    ip_detect: IpDetectConfig,
    entries: std.ArrayList(DdnsEntry),
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PandaConfig) void {
        self.ip_detect.deinit();
        for (self.entries.items) |e| {
            self.allocator.free(e.name);
            self.allocator.free(e.provider);
            self.allocator.free(e.domain);
            self.allocator.free(e.record_type);
            self.allocator.free(e.token);
            self.allocator.free(e.cf_zone_id);
            self.allocator.free(e.custom_url);
            self.allocator.free(e.custom_method);
            self.allocator.free(e.custom_headers);
        }
        self.entries.deinit();
    }
};

pub fn parseConfig(allocator: std.mem.Allocator, path: []const u8) !PandaConfig {
    const file = std.fs.cwd().openFile(path, .{}) catch |e| {
        std.debug.print("ERROR: 无法读取配置文件 {s}: {s}\n", .{ path, @errorName(e) });
        return e;
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 64);
    defer allocator.free(content);

    var global = GlobalConfig{};
    var ip_detect = IpDetectConfig.init(allocator);
    var entries = std.ArrayList(DdnsEntry).init(allocator);

    var current_type = std.ArrayList(u8).init(allocator);
    var current_name = std.ArrayList(u8).init(allocator);
    var opts = std.StringHashMap(std.ArrayList([]const u8)).init(allocator);
    defer {
        current_type.deinit();
        current_name.deinit();
        var iter = opts.iterator();
        while (iter.next()) |kv| {
            kv.value_ptr.deinit();
        }
        opts.deinit();
    }

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        var line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        if (std.mem.startsWith(u8, line, "config ")) {
            flushSection(allocator, &current_type, &current_name, &opts, &global, &ip_detect, &entries);
            current_type.clearRetainingCapacity();
            current_name.clearRetainingCapacity();

            var pieces = std.mem.splitScalar(u8, line["config ".len..], ' ');
            if (pieces.next()) |t| {
                const trimmed = std.mem.trim(u8, t, "'");
                current_type.writer().print("{s}", .{trimmed}) catch {};
            }
            if (pieces.next()) |n| {
                const trimmed = std.mem.trim(u8, n, "'");
                current_name.writer().print("{s}", .{trimmed}) catch {};
            }
        } else if (std.mem.startsWith(u8, line, "option ")) {
            if (current_type.items.len == 0) continue;
            if (parseKv(line["option ".len..])) |kv| {
                const key = allocator.dupe(u8, kv.key) catch continue;
                const val = allocator.dupe(u8, kv.val) catch continue;
                var list = std.ArrayList([]const u8).init(allocator);
                list.append(val) catch {};
                opts.put(key, list) catch {};
            }
        } else if (std.mem.startsWith(u8, line, "list ")) {
            if (current_type.items.len == 0) continue;
            if (parseKv(line["list ".len..])) |kv| {
                const key = allocator.dupe(u8, kv.key) catch continue;
                const val = allocator.dupe(u8, kv.val) catch continue;
                var entry = opts.getOrPut(key) catch continue;
                if (!entry.found_existing) {
                    entry.value_ptr.* = std.ArrayList([]const u8).init(allocator);
                }
                entry.value_ptr.append(val) catch {};
            }
        }
    }
    flushSection(allocator, &current_type, &current_name, &opts, &global, &ip_detect, &entries);

    return PandaConfig{
        .global = global,
        .ip_detect = ip_detect,
        .entries = entries,
        .allocator = allocator,
    };
}

fn parseKv(s: []const u8) ?struct { key: []const u8, val: []const u8 } {
    var trimmed = std.mem.trim(u8, s, " \t");
    const space = std.mem.indexOfScalar(u8, trimmed, ' ') orelse
        std.mem.indexOfScalar(u8, trimmed, '\t') orelse return null;
    const key = std.mem.trim(u8, trimmed[0..space], " \t");
    const val_trimmed = std.mem.trim(u8, trimmed[space + 1 ..], " \t");
    const val = std.mem.trim(u8, val_trimmed, "'");
    return .{ .key = key, .val = val };
}

fn flushSection(
    allocator: std.mem.Allocator,
    current_type: *std.ArrayList(u8),
    current_name: *std.ArrayList(u8),
    opts: *std.StringHashMap(std.ArrayList([]const u8)),
    global: *GlobalConfig,
    ip_detect: *IpDetectConfig,
    entries: *std.ArrayList(DdnsEntry),
) void {
    if (current_type.items.len == 0) return;

    const t = current_type.items;
    const n = current_name.items;

    if (std.mem.eql(u8, t, "panda") or std.mem.eql(u8, t, "panda-rust") or std.mem.eql(u8, t, "panda-zig")) {
        if (std.mem.eql(u8, n, "global")) {
            if (getOpt(opts, "ddns_enabled")) |v| {
                global.enabled = std.mem.eql(u8, v, "1");
            }
            if (getOpt(opts, "ddns_interval")) |v| {
                global.interval = std.fmt.parseInt(u64, v, 10) catch 300;
            }
        } else if (std.mem.eql(u8, n, "ip_detect")) {
            if (opts.get("ipv4_urls")) |urls| {
                if (urls.items.len > 0) {
                    ip_detect.ipv4_urls.clearRetainingCapacity();
                    for (urls.items) |url| {
                        const dup = allocator.dupe(u8, url) catch continue;
                        ip_detect.ipv4_urls.append(dup) catch {};
                    }
                }
            }
            if (opts.get("ipv6_urls")) |urls| {
                if (urls.items.len > 0) {
                    ip_detect.ipv6_urls.clearRetainingCapacity();
                    for (urls.items) |url| {
                        const dup = allocator.dupe(u8, url) catch continue;
                        ip_detect.ipv6_urls.append(dup) catch {};
                    }
                }
            }
        }
    } else if (std.mem.eql(u8, t, "ddns_entry") or std.mem.eql(u8, t, "ddns_entry_rust") or std.mem.eql(u8, t, "ddns_entry_zig")) {
        const entry = DdnsEntry{
            .name = allocator.dupe(u8, n) catch return,
            .enabled = blk: {
                break :blk if (getOpt(opts, "enabled")) |v| std.mem.eql(u8, v, "1") else true;
            },
            .provider = allocator.dupe(u8, getOpt(opts, "provider") orelse "") catch return,
            .domain = allocator.dupe(u8, getOpt(opts, "domain") orelse "") catch return,
            .record_type = allocator.dupe(u8, getOpt(opts, "record_type") orelse "A") catch return,
            .token = allocator.dupe(u8, getOpt(opts, "token") orelse "") catch return,
            .ttl = if (getOpt(opts, "ttl")) |v| std.fmt.parseInt(u64, v, 10) catch 120 else 120,
            .cf_zone_id = allocator.dupe(u8, getOpt(opts, "cf_zone_id") orelse "") catch return,
            .cf_proxied = blk: {
                break :blk if (getOpt(opts, "cf_proxied")) |v| std.mem.eql(u8, v, "1") else false;
            },
            .custom_url = allocator.dupe(u8, getOpt(opts, "custom_url") orelse "") catch return,
            .custom_method = allocator.dupe(u8, getOpt(opts, "custom_method") orelse "GET") catch return,
            .custom_headers = allocator.dupe(u8, getOpt(opts, "custom_headers") orelse "{}") catch return,
        };
        entries.append(entry) catch {};
    }

    // Clear opts for next section
    var iter = opts.iterator();
    while (iter.next()) |kv| {
        kv.value_ptr.deinit();
    }
    opts.clearRetainingCapacity();
}

fn getOpt(opts: *std.StringHashMap(std.ArrayList([]const u8)), key: []const u8) ?[]const u8 {
    if (opts.get(key)) |list| {
        if (list.items.len > 0) return list.items[0];
    }
    return null;
}
