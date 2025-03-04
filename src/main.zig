const std = @import("std");
const fpck = @import("root.zig");
const zargs = @import("zargs");
const Command = zargs.Command;
const Iter = zargs.Iter;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    comptime var section: fpck.Section = .{};
    _ = section.ext("attr1", u16, .{ .default = 6 }).ext("attr2", []const u8, .{ .default = "bye", .length = 6 });
    const Packer = fpck.Packer(
        0x6679_7985,
        1,
        .{ .Json = section.Json(), .Core = section.Core(16) },
        u32,
        fpck.crc32zlib_compute,
    );
    var cwd = std.fs.cwd();

    comptime var cmd: Command = .{ .name = "filepacker", .use_subCmd = "sub" };

    comptime var pack: Command = .{ .name = "pack", .description = "Pack some files" };
    _ = pack.optArg("config", []const u8, .{ .long = "cfg", .help = "Tell me how to pack", .default = "config.json" });
    _ = pack.optArg("from", []const u8, .{ .long = "from", .help = "Tell me a directory to find files", .default = "." });
    _ = pack.optArg("output", []const u8, .{ .short = 'o', .long = "out", .help = "Tell me a path to packed file" });

    comptime var unpack: Command = .{ .name = "unpack", .description = "Unpack to some files" };
    _ = unpack.optArg("to", []const u8, .{ .long = "to", .help = "Tell me a directory to unpack files", .default = "." });
    _ = unpack.optArg("input", []const u8, .{ .short = 'i', .long = "in", .help = "Tell me a path to packed file" });

    comptime var show: Command = .{ .name = "show", .description = "Show which files in it" };
    _ = show.optArg("input", []const u8, .{ .short = 'i', .long = "in", .help = "Tell me a path to packed file" });

    _ = cmd.subCmd(pack).subCmd(unpack).subCmd(show);

    var it = try Iter.init(allocator, .{});
    _ = try it.next();
    defer it.deinit();
    const args = try cmd.parse(&it);

    switch (args.sub) {
        .pack => |a| {
            const json_f = try cwd.openFile(a.config, .{});
            defer json_f.close();
            const json_str = try json_f.reader().readAllAlloc(allocator, 4096);
            defer allocator.free(json_str);

            var packer = try Packer.from_json_str(json_str, allocator);
            defer packer.destory();

            const from = try cwd.openDir(a.from, .{});

            const output_f = try cwd.createFile(a.output, .{});
            defer output_f.close();

            try packer.pack(from, null, output_f.writer().any(), .{ .prefix_header = true });
        },
        .unpack => |a| {
            const input = try cwd.openFile(a.input, .{});
            defer input.close();

            var packer = try Packer.from_header_bin(input.reader().any(), allocator);
            defer packer.destory();

            packer.print();

            const to = try cwd.openDir(a.to, .{});
            try packer.unpack(input.reader().any(), to, .{ .save_header = ".header" });
        },
        .show => |a| {
            const input = try cwd.openFile(a.input, .{});
            defer input.close();

            var packer = try Packer.from_header_bin(input.reader().any(), allocator);
            defer packer.destory();

            packer.print();
        },
    }

    std.debug.print("Success to {s}\n", .{@tagName(args.sub)});
}
