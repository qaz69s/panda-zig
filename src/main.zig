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

    // Redirect stderr to log file (catches all std.debug.print output)
    if (std.fs.cwd().createFile(LOG_FILE, .{ .read = true })) |f| {
        const fd = f.handle;
        _ = std.posix.dup2(fd, std.posix.STDERR_FILENO) catch {};
        f.close();
    } else |e| {
        const stderr = std.io.getStdErr().writer();
        stderr.print("警告: 无法创建日志文件 {s}: {s}\n", .{ LOG_FILE, @errorName(e) }) catch {};
    }

    // Parse CLI args for config path
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const config_path = if (args.len > 1) args[1] else "/etc/config/panda-zig";

    log("Panda Zig DDNS 守护进程已启动 (配置: {s})", .{config_path});

    // Signal handling (check running flag each second)
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
            log("DDNS 已禁用，跳过更新", .{});
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
            var ip: ?[]const u8 = null;
            if (std.mem.eql(u8, cfg.ip_detect.ipv4_get_type, "netInterface") and cfg.ip_detect.ipv4_iface.len > 0) {
                std.debug.print("IPv4 从网卡 {s} 获取\n", .{cfg.ip_detect.ipv4_iface});
                ip = ip_detect.detectIPFromIface(cfg.ip_detect.ipv4_iface, allocator, false) catch null;
            } else {
                ip = ip_detect.detectIP(cfg.ip_detect.ipv4_urls.items, allocator) catch null;
            }
            break :blk ip;
        } else null;
        defer if (ipv4) |ip| allocator.free(ip);

        const ipv6 = if (need_v6) blk: {
            var ip: ?[]const u8 = null;
            if (std.mem.eql(u8, cfg.ip_detect.ipv6_get_type, "netInterface") and cfg.ip_detect.ipv6_iface.len > 0) {
                std.debug.print("IPv6 从网卡 {s} 获取\n", .{cfg.ip_detect.ipv6_iface});
                ip = ip_detect.detectIPFromIface(cfg.ip_detect.ipv6_iface, allocator, true) catch null;
            } else {
                ip = ip_detect.detectIP(cfg.ip_detect.ipv6_urls.items, allocator) catch null;
            }
            break :blk ip;
        } else null;
        defer if (ipv6) |ip| allocator.free(ip);

        if (need_v4 and ipv4 == null) {
            log("错误: 无法获取 IPv4 地址", .{});
        }
        if (need_v6 and ipv6 == null) {
            log("错误: 无法获取 IPv6 地址", .{});
        }

        if (ipv4) |ip| log("当前 IPv4: {s}", .{ip});
        if (ipv6) |ip| log("当前 IPv6: {s}", .{ip});

        var updated: u32 = 0;
        var skipped: u32 = 0;

        for (cfg.entries.items) |*entry| {
            if (!entry.enabled) continue;
            if (entry.provider.len == 0) {
                log("警告: {s} 未设置服务商", .{entry.name});
                continue;
            }

            if (std.ascii.eqlIgnoreCase(entry.record_type, "BOTH")) {
                // Dual-stack
                if (ipv4) |ip| {
                    const key = try std.fmt.allocPrint(allocator, "{s}_{s}", .{ entry.name, "A" });
                    defer allocator.free(key);
                    if (st.isUnchanged(key, ip)) {
                        log("{s} (IPv4): IP 未变，跳过", .{entry.name});
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
                        log("{s} (IPv6): IP 未变，跳过", .{entry.name});
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
                        log("{s}: IP 未变，跳过", .{entry.name});
                        skipped += 1;
                    } else {
                        if (providers.update(allocator, entry, ip_val)) {
                            st.save(entry.name, ip_val) catch {};
                            updated += 1;
                        }
                    }
                } else {
                    log("警告: {s}: 无法获取 IP 地址", .{entry.name});
                }
            }
        }

        if (updated == 0 and skipped == 0) {
            log("无需更新（0 更新 0 跳过）", .{});
        }

        sleepSecs(cfg.global.interval);
    }

    log("Panda Zig DDNS 已停止", .{});
}

fn log(comptime fmt: []const u8, args: anytype) void {
    const stderr = std.io.getStdErr().writer();
    stderr.print(fmt ++ "\n", args) catch {};
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
            log("UCI 配置已变更，重新加载", .{});
        }
        last_mtime.* = mtime;
        return config.parseConfig(allocator, path) catch |e| {
            log("错误: 配置解析失败: {s}", .{@errorName(e)});
            return null;
        };
    }
    return null;
}

fn parseConfigOrExit(allocator: std.mem.Allocator, path: []const u8) config.PandaConfig {
    return config.parseConfig(allocator, path) catch |e| {
        log("错误: 配置解析失败: {s}", .{@errorName(e)});
        std.process.exit(1);
    };
}
