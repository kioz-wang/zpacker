const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addModule("zpacker", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const lib_test = b.addRunArtifact(
        b.addTest(.{ .root_module = lib }),
    );

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&lib_test.step);

    const exe = b.addExecutable(.{
        .name = "zpacker",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("zpacker", lib);
    exe.root_module.addImport("zargs", b.dependency("zargs", .{}).module("zargs"));
    exe.root_module.addImport("ztype", b.dependency("zargs", .{}).module("ztype"));

    b.installArtifact(exe);
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
