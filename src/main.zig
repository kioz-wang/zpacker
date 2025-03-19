const std = @import("std");
const fpkg = @import("root.zig");
const zargs = @import("zargs");
const Command = zargs.Command;
const Arg = zargs.Arg;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const section = blk: {
    var s: fpkg.Section = .{};
    _ = s.ext("attr1", u16, .{ .default = 6 }).ext("attr2", []const u8, .{ .default = "bye", .length = 6 });
    break :blk s;
};
const Packer = fpkg.Packer(0x6679_7985, 1, .{ .Json = section.Json(), .Core = section.Core(16) }, u32, fpkg.crc32zlib_compute);

const show = Command.new("show").about("Show contents of package")
    .arg(Arg.optArg("input", []const u8)
    .short('i').long("in")
    .help("Path of package"));

const pack = Command.new("pack").about("Pack files to a package")
    .arg(Arg.optArg("config", []const u8)
        .long("cfg")
        .help("Howto pack")
        .default("config.json"))
    .arg(Arg.optArg("from", []const u8)
        .long("from")
        .help("Path that find files from")
        .default("."))
    .arg(Arg.optArg("header", ?[]const u8)
        .long("header").help("Path of header"))
    .arg(Arg.optArg("payload", ?[]const u8)
        .long("payload").help("Path of payload"))
    .arg(Arg.optArg("align", u32)
    .long("align").default(1));

const unpack = Command.new("unpack").about("Unpack a package")
    .optArg("to", []const u8, .{ .long = "to", .help = "Path that unpack to", .default = "." })
    .optArg("input", []const u8, .{ .long = "in", .short = 'i', .help = "Path of package" });

const cwd = std.fs.cwd();

fn actionShow(args: *show.Result()) void {
    _ = args;
}
fn actionPack(args: *pack.Result()) void {
    _ = args;
}
fn actionUnpack(args: *unpack.Result()) void {
    _ = args;
}

pub fn main() !void {
    comptime var _show = show;
    comptime _show.callBack(actionShow);
    comptime var _pack = pack;
    comptime _pack.callBack(actionPack);
    comptime var _unpack = unpack;
    comptime _unpack.callBack(actionUnpack);
    const cmd = Command.new("filepacker").requireSub("sub")
        .sub(_show).sub(_pack).sub(_unpack);

    const args = try cmd.parse(allocator);

    switch (args.sub) {
        .pack => |a| {
            const json_f = try cwd.openFile(a.config, .{});
            defer json_f.close();
            const json_str = try json_f.reader().readAllAlloc(allocator, 4096);
            defer allocator.free(json_str);

            var packer = try Packer.from_json_str(json_str, allocator);
            defer packer.destory();

            const from = try cwd.openDir(a.from, .{});

            const output_f = try cwd.createFile(a.payload.?, .{});
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
