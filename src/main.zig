const std = @import("std");
const config = @import("config.zig");
const ip_detect = @import("ip_detect.zig");
const state = @import("state.zig");
const providers = @import("providers/mod.zig");

const LOG_FILE = "/var/log/panda-zig.log";

var running: bool = true;

pub fn main() !void {
    // Allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse CLI args for config path
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const config_path = if (args.len > 1) args[1] else "/etc/config/panda-rust";

    // Setup logging
    try setupLogging();
    std.log.info("Panda Zig DDNS 守护进程启动 (config: {s})", .{config_path});

    // Signal handling (simplified - check flag each second)
    var st = state.State.init(allocator);
    defer st.deinit();

    var last_mtime: u64 = 0;
    var cfg = parseConfigOrExit(allocator, config_path);
    defer cfg.deinit();

    while (running) {
        // Reload config if changed
        if (reloadConfig(allocator, config_path, &last_mtime)) |new_cfg| {
            cfg.deinit();
            cfg = new_cfg;
        }

        if (!cfg.global.enabled) {
            std.log.info("DDNS 已禁用，跳过更新", .{});
            sleepSecs(cfg.global.interval);
            continue;
        }

        var need_v4 = false;
        var need_v6 = false;
        for (cfg.entries.items) |e| {
            if (!e.enabled) continue;
            if (std.ascii.eqlIgnoreCase(e.record_type, "A")) need_v4 = true;
            if (std.ascii.eqlIgnoreCase(e.record_type, "AAAA")) need_v6 = true;
            if (std.ascii.eqlIgnoreCase(e.record_type, "BOTH")) { need_v4 = true; need_v6 = true; }
        }

        // Fetch IPs
        const ipv4 = if (need_v4) blk: {
            break :blk ip_detect.detectIP(cfg.ip_detect.ipv4_urls.items, allocator) catch null;
        } else null;
        defer if (ipv4) |ip| allocator.free(ip);

        const ipv6 = if (need_v6) blk: {
            break :blk ip_detect.detectIP(cfg.ip_detect.ipv6_urls.items, allocator) catch null;
        } else null;
        defer if (ipv6) |ip| allocator.free(ip);

        if (need_v4 and ipv4 == null) {
            std.log.err("无法获取 IPv4 地址", .{});
        }
        if (need_v6 and ipv6 == null) {
            std.log.err("无法获取 IPv6 地址", .{});
        }

        if (ipv4) |ip| std.log.info("当前 IPv4: {s}", .{ip});
        if (ipv6) |ip| std.log.info("当前 IPv6: {s}", .{ip});

        var updated: u32 = 0;
        var skipped: u32 = 0;

        for (cfg.entries.items) |*entry| {
            if (!entry.enabled) continue;
            if (entry.provider.len == 0) {
                std.log.warn("{s}: 未设置服务商", .{entry.name});
                continue;
            }

            if (std.ascii.eqlIgnoreCase(entry.record_type, "BOTH")) {
                // Dual-stack
                if (ipv4) |ip| {
                    const key = try std.fmt.allocPrint(allocator, "{s}_{s}", .{ entry.name, "A" });
                    defer allocator.free(key);
                    if (st.isUnchanged(key, ip)) {
                        std.log.info("{s} (IPv4): IP 未变更，跳过", .{entry.name});
                        skipped += 1;
                    } else {
                        if (providers.update(allocator, entry, ip)) {
                            st.save(key, ip) catch {};
                            updated += 1;
                        }
                    }
                }
                if (ipv6) |ip| {
                    const key = try std.fmt.allocPrint(allocator, "{s}_{s}", .{ entry.name, "AAAA" });
                    defer allocator.free(key);
                    if (st.isUnchanged(key, ip)) {
                        std.log.info("{s} (IPv6): IP 未变更，跳过", .{entry.name});
                        skipped += 1;
                    } else {
                        var e2 = entry.*;
                        e2.record_type = "AAAA";
                        if (providers.update(allocator, &e2, ip)) {
                            st.save(key, ip) catch {};
                            updated += 1;
                        }
                    }
                }
            } else {
                const ip = if (std.ascii.eqlIgnoreCase(entry.record_type, "A")) ipv4 else ipv6;
                if (ip) |ip_val| {
                    if (st.isUnchanged(entry.name, ip_val)) {
                        std.log.info("{s}: IP 未变更，跳过", .{entry.name});
                        skipped += 1;
                    } else {
                        if (providers.update(allocator, entry, ip_val)) {
                            st.save(entry.name, ip_val) catch {};
                            updated += 1;
                        }
                    }
                } else {
                    std.log.warn("{s}: 无法获取 IP 地址", .{entry.name});
                }
            }
        }

        if (updated == 0 and skipped == 0) {
            std.log.info("无已启用的条目需要更新", .{});
        }

        sleepSecs(cfg.global.interval);
    }

    std.log.info("Panda Zig DDNS 已停止", .{});
}

fn setupLogging() !void {
    // Open log file
    const file = std.fs.cwd().createFile(LOG_FILE, .{ .read = true }) catch |e| {
        std.log.warn("无法创建日志文件: {s}", .{@errorName(e)});
        return;
    };
    file.close();
}

fn sleepSecs(secs: u64) void {
    var i: u64 = 0;
    while (i < secs and running) : (i += 1) {
        std.time.sleep(std.time.ns_per_s);
    }
}

fn reloadConfig(allocator: std.mem.Allocator, path: []const u8, last_mtime: *u64) ?config.PandaConfig {
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();
    const stat = file.stat() catch return null;
    const mtime_ns: u64 = @intCast(stat.mtime);
    const mtime = mtime_ns / 1_000_000_000;

    if (mtime > last_mtime.*) {
        if (last_mtime.* != 0) {
            std.log.info("UCI 配置已变更，重新加载", .{});
        }
        last_mtime.* = mtime;
        return config.parseConfig(allocator, path) catch |e| {
            std.log.err("配置解析失败: {s}", .{@errorName(e)});
            return null;
        };
    }
    return null;
}

fn parseConfigOrExit(allocator: std.mem.Allocator, path: []const u8) config.PandaConfig {
    return config.parseConfig(allocator, path) catch |e| {
        std.log.err("配置解析失败: {s}", .{@errorName(e)});
        std.process.exit(1);
    };
}
