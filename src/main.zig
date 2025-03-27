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
    .arg(Arg.posArg("input", []const u8).help("Path of package"));

const pack = Command.new("pack").about("Pack a package from files")
    .arg(Arg.posArg("config", []const u8).help("Howto pack (maxsize 4096) (Try as header binary if fail to parse as json)").default("config.json"))
    .arg(Arg.optArg("from", []const u8).long("from").help("Path that find files from").default("."))
    .arg(Arg.optArg("header", ?[]const u8).long("header").help("Path of header"))
    .arg(Arg.optArg("payload", ?[]const u8).long("payload").help("Path of payload"))
    .arg(Arg.opt("prefix", bool).long("no_prefix").default(true).help("Don't prefix header to payload"))
    .arg(Arg.optArg("chunk", usize).long("chunk").default(4 * 1024 * 1024).help("Chunk bytes per IO"))
    .arg(Arg.optArg("align", u32).long("align").default(1));

const unpack = Command.new("unpack").about("Unpack a package to files")
    .arg(Arg.optArg("to", []const u8).long("to").help("Path that unpack to").default("."))
    .posArg("input", []const u8, .{ .help = "Path of package" })
    .optArg("chunk", usize, .{ .long = "chunk", .default = 4 * 1024 * 1024, .help = "Chunk bytes per IO" })
    .arg(Arg.optArg("header", ?[]const u8).long("save_header").help("Save header to"));

const cwd = std.fs.cwd();
fn exit(status: u8, comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(status);
}

fn actionShow(args: *show.Result()) void {
    const f = cwd.openFile(args.input, .{}) catch |e| {
        exit(1, "fail to open {s} ({})", .{ args.input, e });
    };
    defer f.close();
    var packer = Packer.from_header_bin(f.reader().any(), allocator) catch |e| {
        exit(1, "fail to parse {s} ({})", .{ args.input, e });
    };
    defer packer.destory();
    packer.print();
}

fn actionPack(args: *pack.Result()) void {
    const f = cwd.openFile(args.config, .{}) catch |e| {
        exit(1, "fail to open {s} ({})", .{ args.config, e });
    };
    defer f.close();
    const cont = f.reader().readAllAlloc(allocator, 4096) catch |e| {
        exit(1, "fail to read {s} ({})", .{ args.config, e });
    };
    var packer = Packer.from_json_str(cont, allocator) catch |e_json| bin: {
        std.log.warn("fail to parse as json, try as header binary again ({})", .{e_json});
        f.seekTo(0) catch unreachable;
        break :bin Packer.from_header_bin(f.reader().any(), allocator) catch |e_bin| {
            exit(1, "fail to parse {s} ({})", .{ args.config, e_bin });
        };
    };
    defer packer.destory();

    const payload = if (args.payload) |s| blk: {
        const p = cwd.createFile(s, .{}) catch |e| exit(1, "fail to create payload {s} ({})", .{ s, e });
        break :blk p.writer().any();
    } else null;
    const header = if (args.header) |s| blk: {
        const p = cwd.createFile(s, .{}) catch |e| exit(1, "fail to create header {s} ({})", .{ s, e });
        break :blk p.writer().any();
    } else null;
    const from = cwd.openDir(args.from, .{}) catch |e| exit(1, "fail to openDir({s}) ({})", .{ args.from, e });

    packer.pack(from, header, payload, .{ .prefix_header = args.prefix, .align_ = args.@"align", .chunk = args.chunk, .pad_byte = .{ 0, 0 } }) catch |e| {
        exit(1, "fail to pack ({})", .{e});
    };
}

fn actionUnpack(args: *unpack.Result()) void {
    const f = cwd.openFile(args.input, .{}) catch |e| {
        exit(1, "fail to open {s} ({})", .{ args.input, e });
    };
    defer f.close();
    var packer = Packer.from_header_bin(f.reader().any(), allocator) catch |e| {
        exit(1, "fail to parse {s} ({})", .{ args.input, e });
    };
    defer packer.destory();

    const header = if (args.header) |s| blk: {
        const p = cwd.createFile(s, .{}) catch |e| exit(1, "fail to create header {s} ({})", .{ s, e });
        break :blk p.writer().any();
    } else null;
    const to = cwd.openDir(args.to, .{}) catch |e| exit(1, "fail to openDir({s}) ({})", .{ args.to, e });

    packer.unpack(f.reader().any(), to, .{ .save_header = header, .chunk = args.chunk }) catch |e| {
        exit(1, "fail to unpack ({})", .{e});
    };
}

pub fn main() !void {
    comptime var _show = show;
    comptime _show.callBack(actionShow);
    comptime var _pack = pack;
    comptime _pack.callBack(actionPack);
    comptime var _unpack = unpack;
    comptime _unpack.callBack(actionUnpack);
    comptime var cmd = Command.new("filepacker").requireSub("sub")
        .sub(_show).sub(_pack).sub(_unpack);
    comptime cmd.callBack(struct {
        const C = cmd;
        fn f(r: *C.Result()) void {
            std.log.info("Success {s}", .{@tagName(r.sub)});
        }
    }.f);

    const args = cmd.parse(allocator) catch |e| {
        std.log.err("command parse fail {}", .{e});
        return e;
    };
    defer cmd.destroy(&args, allocator);
}
