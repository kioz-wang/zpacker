const std = @import("std");
const fpkg = @import("root.zig");
const zargs = @import("zargs");
const Command = zargs.Command;
const Arg = zargs.Arg;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const section = fpkg.Section.new()
    .field("attr1", u16, .{ .default = 6 })
    .field("attr2", []const u8, .{ .default = "bye", .length = 6 });
const Packer = fpkg.Packer(0x6679_7985, 1, section, 16, true, u32, fpkg.crc32zlib_compute);

const show = Command.new("show").alias("s")
    .about("Show contents of package")
    .arg(Arg.posArg("input", []const u8).help("Path of package"));

const pack = Command.new("pack").alias("p").alias("as")
    .about("Pack a package from files")
    .arg(Arg.posArg("config", []const u8).help("Howto pack (maxsize 4096) (Try as header binary if fail to parse as json)").default("config.json"))
    .arg(Arg.optArg("from", []const u8).long("from").help("Path that find files from").default("."))
    .arg(Arg.optArg("header", ?[]const u8).long("header").help("Path of header"))
    .arg(Arg.optArg("payload", ?[]const u8).long("payload").help("Path of payload"))
    .arg(Arg.opt("prefix", bool).long("no_prefix").default(true).help("Don't prefix header to payload"))
    .arg(Arg.optArg("chunk", usize).long("chunk").default(4 * 1024 * 1024).help("Chunk bytes per IO"))
    .arg(Arg.optArg("align", u32).long("align").default(1));

const unpack = Command.new("unpack").alias("u").alias("disa")
    .about("Unpack a package to files")
    .arg(Arg.optArg("to", []const u8).long("to").help("Path that unpack to").default("."))
    .posArg("input", []const u8, .{ .help = "Path of package" })
    .optArg("chunk", usize, .{ .long = "chunk", .default = 4 * 1024 * 1024, .help = "Chunk bytes per IO" })
    .arg(Arg.optArg("header", ?[]const u8).long("save_header").help("Save header to"));

fn actionShow(args: *show.Result()) void {
    const cwd = std.fs.cwd();
    const f = cwd.openFile(args.input, .{}) catch |e| {
        zargs.exitf(e, 1, "fail to open {s}", .{args.input});
    };
    defer f.close();
    var packer = Packer.from_header_bin(f.reader().any(), allocator) catch |e| {
        zargs.exitf(e, 1, "fail to parse {s}", .{args.input});
    };
    defer packer.destory();
    packer.print();
}

fn actionPack(args: *pack.Result()) void {
    const cwd = std.fs.cwd();
    const f = cwd.openFile(args.config, .{}) catch |e| {
        zargs.exitf(e, 1, "fail to open {s}", .{args.config});
    };
    defer f.close();
    const cont = f.reader().readAllAlloc(allocator, 4096) catch |e| {
        zargs.exitf(e, 1, "fail to read {s}", .{args.config});
    };
    var packer = Packer.from_json_str(cont, allocator) catch |e_json| bin: {
        std.log.warn("fail to parse as json, try as header binary again ({})", .{e_json});
        f.seekTo(0) catch unreachable;
        break :bin Packer.from_header_bin(f.reader().any(), allocator) catch |e_bin| {
            zargs.exitf(e_bin, 1, "fail to parse {s}", .{args.config});
        };
    };
    defer packer.destory();

    const payload = if (args.payload) |s| blk: {
        const p = cwd.createFile(s, .{}) catch |e| zargs.exitf(e, 1, "fail to create payload {s}", .{s});
        break :blk p.writer().any();
    } else null;
    const header = if (args.header) |s| blk: {
        const p = cwd.createFile(s, .{}) catch |e| zargs.exitf(e, 1, "fail to create header {s}", .{s});
        break :blk p.writer().any();
    } else null;
    const from = cwd.openDir(args.from, .{}) catch |e| zargs.exitf(e, 1, "fail to openDir({s})", .{args.from});

    packer.pack(from, header, payload, .{ .prefix_header = args.prefix, .align_ = args.@"align", .chunk = args.chunk, .pad_byte = .{ 0, 0 } }) catch |e| {
        zargs.exitf(e, 1, "fail to pack", .{});
    };
}

fn actionUnpack(args: *unpack.Result()) void {
    const cwd = std.fs.cwd();
    const f = cwd.openFile(args.input, .{}) catch |e| {
        zargs.exitf(e, 1, "fail to open {s}", .{args.input});
    };
    defer f.close();
    var packer = Packer.from_header_bin(f.reader().any(), allocator) catch |e| {
        zargs.exitf(e, 1, "fail to parse {s}", .{args.input});
    };
    defer packer.destory();

    const to = cwd.openDir(args.to, .{}) catch |e| zargs.exitf(e, 1, "fail to openDir({s})", .{args.to});
    const header = if (args.header) |s| blk: {
        const p = to.createFile(s, .{}) catch |e| zargs.exitf(e, 1, "fail to create header {s}", .{s});
        break :blk p.writer().any();
    } else null;

    packer.unpack(f.reader().any(), to, .{ .save_header = header, .chunk = args.chunk }) catch |e| {
        zargs.exitf(e, 1, "fail to unpack", .{});
    };
}

const app = Command.new("filepacker").requireSub("action")
    .version("0.1.3").author("Kioz Wang")
    .sub(show.callBack(actionShow))
    .sub(pack.callBack(actionPack))
    .sub(unpack.callBack(actionUnpack));

pub fn main() !void {
    const args = app.callBack(struct {
        fn f(r: *app.Result()) void {
            std.log.info("Success {s}", .{@tagName(r.action)});
        }
    }.f).parse(allocator) catch |e| {
        std.log.err("command parse fail {}", .{e});
        return e;
    };
    defer app.destroy(&args, allocator);
}
