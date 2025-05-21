const std = @import("std");
const fpkg = @import("root.zig");
const zargs = @import("zargs");
const Command = zargs.Command;
const Arg = zargs.Arg;
const Ranges = zargs.Ranges;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const section = fpkg.Section.new()
    .field("attr1", u16, .{ .default = 6 })
    .field("attr2", []const u8, .{ .default = "bye", .length = 6 });
const Packer = fpkg.Packer(0x6679_7985, 1, section, 16, false, u32, fpkg.crc32zlib_compute);

const show = Command.new("show").alias("s")
    .about("Show contents of package")
    .arg(Arg.posArg("input", []const u8).help("Path of package"));

const pack = Command.new("pack").alias("p").alias("as")
    .about("Pack a package from files")
    .arg(Arg.posArg("config", []const u8).help("Howto pack (maxsize 4096) (Try as header binary if fail to parse as json)").default("config.json"))
    .arg(Arg.optArg("from", []const u8).long("from").help("Path that find files from").default("."))
    .arg(Arg.optArg("literal_files", []const fpkg.LiteralFile).long("file").help("Specify the content of a file").argName("(name=[content])"))
    .arg(Arg.optArg("header", ?[]const u8).long("header").help("Path of header"))
    .arg(Arg.optArg("payload", []const u8).long("payload").help("Path of payload"))
    .arg(Arg.opt("prefix", bool).long("no_prefix").default(true).help("Don't prefix header to payload"))
    .arg(Arg.optArg("chunk", usize).long("chunk").default(4 * 1024 * 1024).help("Chunk bytes per IO"))
    .arg(Arg.optArg("align", u32).long("align").default(1).ranges(Ranges(u32).new().u(1, null)))
    .arg(Arg.optArg("pad_byte", u8).long("pad_byte").default(0).help("Fill when {ALIGN} > 1"))
    .arg(Arg.optArg("digest_type", fpkg.DigestType).long("digest"));

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
    var packer = Packer.from_header_bin(f, allocator) catch |e| {
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
    const cont = f.reader().readAllAlloc(allocator, 64 * 1024) catch |e| {
        zargs.exitf(e, 1, "fail to read {s}", .{args.config});
    };
    var packer = Packer.from_json_str(
        cont,
        allocator,
        .{ .digest_type = args.digest_type, .align32 = args.@"align", .pad_byte = args.pad_byte },
    ) catch |e_json| bin: {
        std.log.warn("fail to parse as json, try as header binary again ({})", .{e_json});
        f.seekTo(0) catch unreachable;
        const p = Packer.from_header_bin(f, allocator) catch |e_bin| {
            zargs.exitf(e_bin, 1, "fail to parse {s}", .{args.config});
        };
        if (p.core.digest_type != args.digest_type) {
            std.log.warn("keep digest_type {s} instead of {s}", .{ @tagName(p.core.digest_type), @tagName(args.digest_type) });
        }
        if (p.core.align32 != args.@"align") {
            std.log.warn("keep align {x} instead of {x}", .{ p.core.align32, args.@"align" });
        }
        if (p.core.align32 != 1 and p.padding[0] != args.pad_byte) {
            std.log.warn("keep pad_byte {x:02} instead of {x:02}", .{ p.padding[0], args.pad_byte });
        }
        break :bin p;
    };
    defer packer.destory();

    const payload = cwd.createFile(args.payload, .{}) catch |e|
        zargs.exitf(e, 1, "fail to create payload {s}", .{args.payload});
    const header = if (args.header) |s|
        cwd.createFile(s, .{}) catch |e|
            zargs.exitf(e, 1, "fail to create header {s}", .{s})
    else
        null;
    const from = cwd.openDir(args.from, .{}) catch |e|
        zargs.exitf(e, 1, "fail to openDir({s})", .{args.from});

    packer.pack(
        from,
        args.literal_files,
        header,
        payload,
        .{ .prefix_header = args.prefix, .chunk = args.chunk },
    ) catch |e| {
        zargs.exitf(e, 1, "fail to pack", .{});
    };
}

fn actionUnpack(args: *unpack.Result()) void {
    const cwd = std.fs.cwd();
    const f = cwd.openFile(args.input, .{}) catch |e| {
        zargs.exitf(e, 1, "fail to open {s}", .{args.input});
    };
    defer f.close();
    var packer = Packer.from_header_bin(f, allocator) catch |e| {
        zargs.exitf(e, 1, "fail to parse {s}", .{args.input});
    };
    defer packer.destory();

    const to = cwd.openDir(args.to, .{}) catch |e|
        zargs.exitf(e, 1, "fail to openDir({s})", .{args.to});
    const header = if (args.header) |s|
        to.createFile(s, .{}) catch |e| zargs.exitf(e, 1, "fail to create header {s}", .{s})
    else
        null;

    packer.unpack(f, to, .{ .save_header = header, .chunk = args.chunk }) catch |e| {
        zargs.exitf(e, 1, "fail to unpack", .{});
    };
}

const app = Command.new("filepacker").requireSub("action")
    .version("0.2.0").author("Kioz Wang")
    .sub(show.callBack(actionShow))
    .sub(pack.callBack(actionPack))
    .sub(unpack.callBack(actionUnpack));

pub fn main() !void {
    const args = app.callBack(struct {
        fn f(r: *app.Result()) void {
            std.log.info("Action({s}) Done", .{@tagName(r.action)});
        }
    }.f).parse(allocator) catch |e| {
        std.log.err("command parse fail {}", .{e});
        return e;
    };
    defer app.destroy(&args, allocator);
}
