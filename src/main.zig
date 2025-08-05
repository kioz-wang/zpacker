const std = @import("std");
const zpacker = @import("zpacker");
const zargs = @import("zargs");
const Command = zargs.Command;
const Arg = zargs.Arg;
const Ranges = zargs.Ranges;
const ztype = @import("ztype");
const String = ztype.String;
const Open = ztype.Open;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const section = zpacker.Section.new()
    .field("attr1", u16, .{ .default = 6 })
    .field("attr2", []const u8, .{ .default = "bye", .length = 6 });
const Packer = zpacker.Packer(0x6679_7985, 1, section, 16, false, u32, zpacker.crc32zlib_compute);

const show = Command.new("show").alias("s")
    .about("Show contents of package")
    .arg(Arg.posArg("input", Open(.file, .{})).help("Path of package"));

const pack = Command.new("pack").alias("p").alias("as")
    .about("Pack a package from files")
    .arg(Arg.posArg("config", Open(.file, .{})).help("Howto pack (maxsize 4096) (Try as header binary if fail to parse as json)").rawDefault("config.json"))
    .arg(Arg.optArg("froms", []Open(.dir, .{})).long("from").argName("DIR").help("Path that find files from"))
    .arg(Arg.optArg("literal_files", []zpacker.LiteralFile).long("file").help("Specify the content of a file").argName("(name=[content])"))
    .arg(Arg.optArg("header", ?Open(.fileCreate, .{})).long("header").help("Path of header"))
    .arg(Arg.optArg("payload", Open(.fileCreate, .{})).long("payload").help("Path of payload"))
    .arg(Arg.opt("prefix", bool).long("no_prefix").default(true).help("Don't prefix header to payload"))
    .arg(Arg.optArg("chunk", usize).long("chunk").default(4 * 1024 * 1024).help("Chunk bytes per IO"))
    .arg(Arg.optArg("align", u32).long("align").default(1).ranges(Ranges(u32).new().u(1, null)))
    .arg(Arg.optArg("pad_byte", u8).long("pad_byte").default(0).help("Fill when {ALIGN} > 1"))
    .arg(Arg.optArg("digest_type", zpacker.DigestType).long("digest"));

const unpack = Command.new("unpack").alias("u").alias("disa")
    .about("Unpack a package to files")
    .arg(Arg.optArg("to", Open(.dir, .{})).long("to").help("Path that unpack to").rawDefault("."))
    .posArg("input", Open(.file, .{}), .{ .help = "Path of package" })
    .optArg("chunk", usize, .{ .long = "chunk", .default = 4 * 1024 * 1024, .help = "Chunk bytes per IO" })
    .arg(Arg.optArg("header", ?String).long("save_header").help("Save header to"));

fn actionShow(args: *show.Result()) void {
    var packer = Packer.from_header_bin(args.input.v, allocator) catch |e| {
        zargs.exitf(e, 1, "fail to parse {}", .{args.input});
    };
    defer packer.destory();
    packer.print();
}

fn actionPack(args: *pack.Result()) void {
    const cont = args.config.v.reader().readAllAlloc(allocator, 64 * 1024) catch |e| {
        zargs.exitf(e, 1, "fail to read {}", .{args.config});
    };
    var packer = Packer.from_json_str(
        cont,
        allocator,
        .{ .digest_type = args.digest_type, .align32 = args.@"align", .pad_byte = args.pad_byte },
    ) catch |e_json| bin: {
        std.log.warn("fail to parse as json, try as header binary again ({})", .{e_json});
        args.config.v.seekTo(0) catch unreachable;
        const p = Packer.from_header_bin(args.config.v, allocator) catch |e_bin| {
            zargs.exitf(e_bin, 1, "fail to parse {}", .{args.config});
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

    var froms = allocator.alloc(std.fs.Dir, if (args.froms.len == 0) 1 else args.froms.len) catch |err| zargs.exit(err, 1);
    defer allocator.free(froms);
    if (args.froms.len == 0) {
        froms[0] = std.fs.cwd();
    } else {
        for (froms, args.froms) |*f, af| {
            f.* = af.v;
        }
    }
    packer.pack(
        froms,
        args.literal_files,
        if (args.header) |h| h.v else null,
        args.payload.v,
        .{ .prefix_header = args.prefix, .chunk = args.chunk },
    ) catch |e| {
        zargs.exitf(e, 1, "fail to pack", .{});
    };
}

fn actionUnpack(args: *unpack.Result()) void {
    var packer = Packer.from_header_bin(args.input.v, allocator) catch |e| {
        zargs.exitf(e, 1, "fail to parse {}", .{args.input});
    };
    defer packer.destory();

    const header = if (args.header) |s|
        args.to.v.createFile(s, .{}) catch |e| zargs.exitf(e, 1, "fail to create header {s}", .{s})
    else
        null;

    packer.unpack(args.input.v, args.to.v, .{ .save_header = header, .chunk = args.chunk }) catch |e| {
        zargs.exitf(e, 1, "fail to unpack", .{});
    };
}

const app = Command.new("zpacker").requireSub("action")
    .version("0.2.1").author("Kioz Wang")
    .sub(show.callBack(actionShow))
    .sub(pack.callBack(actionPack))
    .sub(unpack.callBack(actionUnpack))
    .config(.{ .style = .classic });

pub fn main() !void {
    var args = app.callBack(struct {
        fn f(r: *app.Result()) void {
            std.log.info("Action({s}) Done", .{@tagName(r.action)});
        }
    }.f).parse(allocator) catch |e|
        zargs.exitf(e, 1, "\n{s}\n", .{app.usageString()});
    defer app.destroy(&args, allocator);
}
