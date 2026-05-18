const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .musl,
        },
    });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const exe = b.addExecutable(.{
        .name = "panda-zig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.link_function_sections = true;

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run panda-zig");
    run_step.dependOn(&run_cmd.step);
}
