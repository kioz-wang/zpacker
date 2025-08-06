const std = @import("std");
const testing = std.testing;

const StructField = std.builtin.Type.StructField;

fn upAlign(I: type, i: I, align_: I) I {
    return @divTrunc(i, align_) * align_ + if (@rem(i, align_) == 0) 0 else align_;
}

test "Up Align" {
    try testing.expectEqual(0x100, upAlign(u32, 0x9, 0x100));
    try testing.expectEqual(0x100, upAlign(u32, 0x100, 0x100));
    try testing.expectEqual(0x1300, upAlign(u32, 0x1234, 0x100));
    try testing.expectEqual(20, upAlign(u8, 11, 10));
    try testing.expectEqual(20, upAlign(u8, 15, 10));
    try testing.expectEqual(21, upAlign(u8, 16, 7));
    try testing.expectEqual(21, upAlign(u8, 21, 7));
}

fn initArray(T: type, init: []const T, LENGTH: comptime_int) [LENGTH]T {
    var arr = std.mem.zeroes([LENGTH]T);
    @memcpy(arr[0..init.len], init);
    return arr;
}

test "Init Array" {
    const ARR = [10]u8{ 'h', 'e', 'l', 'l', 'o', 0, 0, 0, 0, 1 };
    var arr = initArray(u8, "hello", 10);
    arr[arr.len - 1] = 1;
    try testing.expect(arr.len == 10);
    try testing.expectEqualDeep(ARR, arr);
}

pub const LiteralFile = struct {
    name: []const u8,
    content: []const u8,
    const Self = @This();
    pub fn parse(s: []const u8, a_maybe: ?std.mem.Allocator) ?Self {
        const i = std.mem.indexOf(u8, s, "=") orelse return null;
        if (i == 0) return null;
        const name = a_maybe.?.alloc(u8, i) catch return null;
        const content = a_maybe.?.alloc(u8, s.len - i - 1) catch return null;
        @memcpy(name, s[0..i]);
        @memcpy(content, s[i + 1 ..]);
        return .{ .name = name, .content = content };
    }
    pub fn destroy(self: *Self, a_maybe: ?std.mem.Allocator) void {
        a_maybe.?.free(self.name);
        a_maybe.?.free(self.content);
    }
    pub fn find(files: []const Self, name: []const u8) ?Self {
        for (files) |file| {
            if (std.mem.eql(u8, file.name, name)) {
                return file;
            }
        }
        return null;
    }
};

test "Literal Files" {
    try testing.expectEqual(null, LiteralFile.parse("=", null));
    try testing.expectEqual(null, LiteralFile.parse("f0", null));

    const f0 = LiteralFile.parse("f0=abc", testing.allocator) orelse unreachable;
    defer f0.destroy(testing.allocator);
    try testing.expectEqualDeep(LiteralFile{ .name = "f0", .content = "abc" }, f0);

    const f1 = LiteralFile.parse("f1=", testing.allocator) orelse unreachable;
    defer f1.destroy(testing.allocator);
    try testing.expectEqualDeep(LiteralFile{ .name = "f1", .content = "" }, f1);

    const fs: []const LiteralFile = &.{ f0, f1 };
    try testing.expectEqualDeep(f0, LiteralFile.find(fs, "f0"));
    try testing.expectEqualDeep(f1, LiteralFile.find(fs, "f1"));
    try testing.expectEqual(null, LiteralFile.find(fs, "f2"));
}

pub const Section = struct {
    const Self = @This();
    json_exts: []const StructField,
    core_exts: []const StructField,

    pub fn new() Self {
        return .{ .json_exts = &.{}, .core_exts = &.{} };
    }
    pub fn field(self: Self, name: [:0]const u8, T: type, config: struct {
        default: ?T = null,
        length: usize = 0,
    }) Self {
        var section = self;
        const json_default: ?*const anyopaque = if (config.default) |d| @ptrCast(&d) else null;
        var core_default: ?*const anyopaque = json_default;
        switch (@typeInfo(T)) {
            .int, .float, .bool, .@"enum" => {
                if (config.length != 0) {
                    @compileError("length must be 0 when " ++ @typeName(T));
                }
            },
            else => {
                if (T != []const u8) {
                    @compileError("unsupport type " ++ @typeName(T));
                } else {
                    if (config.length == 0) {
                        @compileError("length mustn't be 0 when " ++ @typeName(T));
                    }
                    if (config.default) |d| {
                        if (d.len > config.length) {
                            @compileError("default {" ++ d ++ "} overflow");
                        }
                    }
                }
                const a = std.mem.zeroes([config.length]u8);
                core_default = @ptrCast(a[0..]);
            },
        }

        const JsonT = T;
        section.json_exts = section.json_exts ++ [_]StructField{.{
            .alignment = @alignOf(JsonT),
            .default_value_ptr = json_default,
            .is_comptime = false,
            .name = name,
            .type = JsonT,
        }};

        const CoreT = if (T == []const u8) @Type(.{ .array = .{
            .len = config.length,
            .child = u8,
            .sentinel_ptr = null,
        } }) else T;
        section.core_exts = section.core_exts ++ [_]StructField{.{
            .alignment = @alignOf(CoreT),
            .default_value_ptr = core_default,
            .is_comptime = false,
            .name = name,
            .type = CoreT,
        }};
        return section;
    }
    pub fn Json(self: Self) type {
        const Simple = struct {
            filename: []const u8,
        };
        var s = @typeInfo(Simple).@"struct";
        s.fields = s.fields ++ self.json_exts;
        return @Type(.{ .@"struct" = s });
    }
    pub fn Core(self: Self, FN_MAXSIZE: comptime_int, comptime big: bool) type {
        const Simple = extern struct {
            filename: [FN_MAXSIZE]u8 = std.mem.zeroes([FN_MAXSIZE]u8),
            offset: if (big) u64 else u32 = 0,
            length: if (big) u64 else u32 = 0,
        };
        var s = @typeInfo(Simple).@"struct";
        s.fields = s.fields ++ self.core_exts;
        return @Type(.{ .@"struct" = s });
    }
    pub fn json2core(JsonT: type, CoreT: type, json: *const JsonT) CoreT {
        var core = CoreT{};
        inline for (@typeInfo(JsonT).@"struct".fields) |f| {
            if (f.type == []const u8) {
                @memcpy(@field(core, f.name)[0..@field(json, f.name).len], @field(json, f.name));
            } else {
                @field(core, f.name) = @field(json, f.name);
            }
        }
        return core;
    }
};

test "JsonSection parse Simple" {
    const JSON_STR: []const u8 =
        \\ {
        \\   "filename": "file0"
        \\ }
    ;
    const section = Section.new();
    const parsed = try std.json.parseFromSlice(section.Json(), testing.allocator, JSON_STR, .{});
    defer parsed.deinit();
    const json_section = parsed.value;
    try testing.expectEqualStrings("file0", json_section.filename);
}

test "JsonSection parse Ext" {
    const JSON_STR: []const u8 =
        \\ [
        \\   {
        \\     "filename": "file0",
        \\     "attr1": "hello",
        \\     "attr2": 3
        \\   },
        \\   {
        \\     "filename": "file1",
        \\     "attr1": "world"
        \\   }
        \\ ] 
    ;
    const section = Section.new()
        .field("attr1", []const u8, .{ .length = 6 })
        .field("attr2", u32, .{ .default = 9 })
        .field("attr3", []const u8, .{ .default = "bye", .length = 10 });
    const parsed = try std.json.parseFromSlice([]section.Json(), testing.allocator, JSON_STR, .{});
    defer parsed.deinit();
    const json_sections = parsed.value;
    try testing.expect(2 == json_sections.len);
    try testing.expectEqualDeep(section.Json(){
        .filename = "file0",
        .attr1 = "hello",
        .attr2 = 3,
        .attr3 = "bye",
    }, json_sections[0]);
    try testing.expectEqualDeep(section.Json(){
        .filename = "file1",
        .attr1 = "world",
        .attr2 = 9,
        .attr3 = "bye",
    }, json_sections[1]);
}

test "CoreSection Simple" {
    const JSON_STR: []const u8 =
        \\ {
        \\   "filename": "file0"
        \\ }
    ;
    const section = Section.new();
    const parsed = try std.json.parseFromSlice(section.Json(), testing.allocator, JSON_STR, .{});
    defer parsed.deinit();
    var core_section = Section.json2core(section.Json(), section.Core(5, false), &parsed.value);
    core_section.length = 1;
    const CORE = section.Core(5, false){ .filename = initArray(u8, "file0", 5), .length = 1 };
    try testing.expectEqualDeep(CORE, core_section);
}

test "CoreSection Ext" {
    const JSON_STR: []const u8 =
        \\ {
        \\   "filename": "file0",
        \\   "attr1": "hello",
        \\   "attr2": 3
        \\ }
    ;
    const section = Section.new()
        .field("attr1", []const u8, .{ .length = 6 })
        .field("attr2", u32, .{ .default = 9 })
        .field("attr3", []const u8, .{ .default = "bye", .length = 10 });
    const parsed = try std.json.parseFromSlice(section.Json(), testing.allocator, JSON_STR, .{});
    defer parsed.deinit();
    const json_section = parsed.value;
    try testing.expectEqualStrings("file0", json_section.filename);
    var core_section = Section.json2core(section.Json(), section.Core(32, false), &json_section);
    core_section.length = 1;
    const CORE = section.Core(32, false){
        .filename = initArray(u8, "file0", 32),
        .length = 1,
        .attr1 = initArray(u8, "hello", 6),
        .attr2 = 3,
        .attr3 = initArray(u8, "bye", 10),
    };
    try testing.expectEqualDeep(CORE, core_section);
}

/// python3 zlib.crc32 中使用了快表 https://github.com/python/cpython/blob/main/Modules/binascii.c#L683
///
/// zlib-ng 注释( https://github.com/zlib-ng/zlib-ng/blob/develop/crc32_braid_tbl.h#L5 )提到 Generated automatically by makecrct.c
pub const Crc32Zlib = struct {
    init: u32 = 0,
    /// https://github.com/zlib-ng/zlib-ng/blob/develop/tools/makecrct.c#L62-L80
    fn make_table() [256]u32 {
        // p(x) reflected, with x^32 implied
        const POLY: u32 = 0xedb8_8320;
        var table: [256]u32 = undefined;
        var p: u32 = undefined;
        @setEvalBranchQuota(3000);
        for (0..256) |i| {
            p = @intCast(i);
            for (0..8) |_| {
                p = if (p & 1 != 0) (p >> 1) ^ POLY else p >> 1;
            }
            table[i] = p;
        }
        return table;
    }
    const TABLE = make_table();

    pub fn print_table() void {
        for (0..256) |i| {
            std.debug.print("0x{x:0>8}{s}", .{ TABLE[i], if (i == 256) "" else if (i % 5 == 4) ",\n" else ", " });
        }
    }
    pub fn compute(self: *const @This(), data: []const u8) u32 {
        var result: u32 = undefined;
        var crc: u32 = ~self.init;
        for (data) |c| {
            crc = TABLE[(crc ^ c) & 0xff] ^ (crc >> 8);
        }
        result = crc ^ 0xFFFF_FFFF;
        return result & 0xFFFF_FFFF;
    }
};

test "Crc32Zlib" {
    const crc32 = Crc32Zlib{};
    const data0 = initArray(u8, "hello", 20);
    const data1 = initArray(u8, "world", 10);
    try testing.expect(0x4268_ce1c == crc32.compute(data0[0..]));
    try testing.expect(0x45c3_45d2 == crc32.compute(data1[0..]));
}

pub const crc32zlib_compute = f: {
    break :f struct {
        fn compute(data: []const u8) u32 {
            const c: Crc32Zlib = .{};
            return c.compute(data);
        }
    }.compute;
};

const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;
const File = std.fs.File;

fn streamCopy(from: std.io.AnyReader, to: std.io.AnyWriter, chunk: usize, max_bytes: ?usize, allocator: std.mem.Allocator) !usize {
    const buffer = try allocator.alloc(u8, chunk);
    defer allocator.free(buffer);
    var expect: usize = chunk;
    var actual: usize = 0;
    var total: usize = 0;
    var remain_bytes = max_bytes;
    while (true) {
        if (remain_bytes) |*remain| {
            if (remain.* == 0) break;
            if (expect > remain.*) {
                expect = remain.*;
            }
            remain.* -= expect;
        }
        actual = try from.readAll(buffer[0..expect]);
        try to.writeAll(buffer[0..actual]);
        total += actual;
        if (actual != expect) break;
    }
    return total;
}

const log = std.log.scoped(.packer);

pub const DigestType = enum(u8) {
    sha256,
    sha1,
    md5,
    pub fn length(self: @This()) usize {
        const hash = std.crypto.hash;
        return switch (self) {
            .sha1 => hash.Sha1.digest_length,
            .sha256 => hash.sha2.Sha256.digest_length,
            .md5 => hash.Md5.digest_length,
        };
    }
};

const Digest = union(DigestType) {
    const Self = @This();
    const hash = std.crypto.hash;
    sha256: hash.sha2.Sha256,
    sha1: hash.Sha1,
    md5: hash.Md5,

    fn compute(digest_type: DigestType, data: []const u8, out: []u8) void {
        if (out.len < digest_type.length()) unreachable;
        switch (digest_type) {
            .sha1 => hash.Sha1.hash(data, @ptrCast(out), .{}),
            .sha256 => hash.sha2.Sha256.hash(data, @ptrCast(out), .{}),
            .md5 => hash.Md5.hash(data, @ptrCast(out), .{}),
        }
    }

    fn init(digest_type: DigestType) Self {
        return switch (digest_type) {
            .sha1 => .{ .sha1 = hash.Sha1.init(.{}) },
            .sha256 => .{ .sha256 = hash.sha2.Sha256.init(.{}) },
            .md5 => .{ .md5 = hash.Md5.init(.{}) },
        };
    }
    fn update(self: *Self, data: []const u8) void {
        switch (self.*) {
            inline .sha1, .sha256, .md5 => |*h| h.update(data),
        }
    }
    fn final(self: *Self, out: []u8) void {
        if (out.len < DigestType.length(self.*)) unreachable;
        switch (self.*) {
            inline .sha1, .sha256, .md5 => |*h| h.final(@ptrCast(out)),
        }
    }
    fn finalCheck(self: *Self, data: []const u8, allocator: Allocator) !bool {
        const length = DigestType.length(self.*);
        if (data.len < length) unreachable;
        const buffer = try allocator.alloc(u8, length);
        defer allocator.free(buffer);
        self.final(buffer);
        return std.mem.eql(u8, data[0..length], buffer);
    }

    pub const Error = error{};
    pub const Writer = std.io.Writer(*Self, Error, write);
    fn write(self: *Self, bytes: []const u8) Error!usize {
        self.update(bytes);
        return bytes.len;
    }
    pub fn writer(self: *Self) Writer {
        return .{ .context = self };
    }
};

pub fn Packer(
    MAGIC: comptime_int,
    VERSION: comptime_int,
    section_: Section,
    FN_MAXSIZE: comptime_int,
    big_file: bool,
    Chksum_T: type,
    Chksum_F: fn ([]const u8) Chksum_T,
) type {
    const DIGEST_MAX_LENGTH = DigestType.sha256.length();

    const Core = extern struct {
        magic: u32 = MAGIC,
        version: u32 = VERSION,
        length: u32,
        section_num: u32,
        digest: [DIGEST_MAX_LENGTH]u8 = std.mem.zeroes([DIGEST_MAX_LENGTH]u8),
        digest_type: DigestType,
        resv: [3]u8 = std.mem.zeroes([3]u8),
        align32: u32 = 1,
    };
    const SectionJ = section_.Json();
    const SectionC = section_.Core(FN_MAXSIZE, big_file);
    const OffsetT = @FieldType(SectionC, "offset");

    return struct {
        const Self = @This();
        core: *align(1) Core,
        sections: []align(1) SectionC,
        padding: []align(1) u8,
        chksum: *align(1) Chksum_T,

        inner: []u8,
        allocator: Allocator,
        unpackable: bool = false,

        fn alloc(core: *const Core, allocator: Allocator) !Self {
            const length = @sizeOf(Core) + @sizeOf(SectionC) * core.section_num;
            const padding_size = core.length - length - @sizeOf(Chksum_T);

            var buffer = try allocator.alloc(u8, core.length);
            errdefer allocator.free(buffer);

            const self = Self{
                .inner = buffer,
                .allocator = allocator,
                .core = @ptrCast(buffer),
                .sections = @as([*]align(1) SectionC, @ptrCast(&buffer[@sizeOf(Core)]))[0..core.section_num],
                .padding = @as([*]u8, @ptrCast(&buffer[length]))[0..padding_size],
                .chksum = @ptrCast(&buffer[core.length - @sizeOf(Chksum_T)]),
            };
            self.core.* = core.*;
            return self;
        }
        pub fn from_json_str(
            json_str: []const u8,
            allocator: Allocator,
            config: struct { digest_type: DigestType, align32: u32 = 1, pad_byte: u8 = 0xf1 },
        ) !Self {
            const parsed = try std.json.parseFromSlice([]SectionJ, allocator, json_str, .{});
            defer parsed.deinit();
            const sectionjs = parsed.value;

            if (config.align32 == 0) unreachable;
            const core = Core{
                .length = @intCast(upAlign(usize, @sizeOf(Core) + @sizeOf(SectionC) * sectionjs.len + @sizeOf(Chksum_T), config.align32)),
                .section_num = @intCast(sectionjs.len),
                .digest_type = config.digest_type,
                .align32 = config.align32,
            };
            const self = try Self.alloc(&core, allocator);
            @memset(self.padding, config.pad_byte);

            for (self.sections, sectionjs) |*section, sectionj| {
                section.* = Section.json2core(SectionJ, SectionC, &sectionj);
            }
            return self;
        }
        pub fn from_header_bin(header: File, allocator: Allocator) !Self {
            const core = try header.reader().readStruct(Core);
            if (core.magic != MAGIC) {
                log.debug("Magic Mismatch, expect {x} but {x}", .{ MAGIC, core.magic });
                return error.MAGIC_MISMATCH;
            }
            if (core.version != VERSION) {
                log.debug("Version Mismatch, expect {x} but {x}", .{ VERSION, core.version });
                return error.VERSION_MISMATCH;
            }

            var self = try Self.alloc(&core, allocator);
            self.unpackable = true;

            if (try header.readAll(self.inner[@sizeOf(Core)..]) != core.length - @sizeOf(Core)) {
                return error.EndOfStream;
            }
            const chksum = Chksum_F(self.inner[0 .. core.length - @sizeOf(Chksum_T)]);
            if (self.chksum.* != chksum) {
                log.debug("Chksum Mismatch, expect {x} but {x}", .{ self.chksum.*, chksum });
                return error.CHKSUM_MISMATCH;
            }
            return self;
        }
        pub fn destory(self: *const Self) void {
            self.allocator.free(self.inner);
        }
        pub fn print(self: *const Self) void {
            const core = self.core;
            log.info("Magic {x:0>8} Version {d} Length {d} SectionNum {d}", .{
                core.magic,
                core.version,
                core.length,
                core.section_num,
            });
            log.info("{s} = {s}", .{
                @tagName(core.digest_type),
                std.fmt.fmtSliceHexUpper(core.digest[0..core.digest_type.length()]),
            });
            for (self.sections, 0..) |*section, i| {
                log.info("Sections[{d}] {x:0>8},{x:0>8} {s}", .{ i, section.offset, section.length, section.filename });
                inline for (std.meta.fields(SectionC)) |field| {
                    if (!(std.mem.eql(u8, "filename", field.name) or std.mem.eql(u8, "offset", field.name) or std.mem.eql(u8, "length", field.name))) {
                        const info = @typeInfo(field.type);
                        if (info == .array and info.array.child == u8) {
                            log.info("  " ++ field.name ++ " {s}", .{@field(section, field.name)});
                        } else {
                            log.info("  " ++ field.name ++ " {d}", .{@field(section, field.name)});
                        }
                    }
                }
            }
            if (self.padding.len == 0) {
                log.info("Align {x}", .{core.align32});
            } else {
                log.info("Align {x} Pad Byte {x:02}", .{ core.align32, self.padding[0] });
            }
            log.info("Chksum is {x:0>8}", .{self.chksum.*});

            const last = &self.sections[self.sections.len - 1];
            const payload_size = last.offset + upAlign(OffsetT, last.length, core.align32);
            log.info("Payload Size {x:0>8} Package Size {x:0>8}", .{ payload_size, payload_size + core.length });
        }
        pub fn pack(
            self: *Self,
            froms: []const Dir,
            literal_files: []const LiteralFile,
            header: ?File,
            payload: File,
            config: struct { prefix_header: bool = false, chunk: usize = 4096 },
        ) !void {
            var offset: OffsetT = 0;
            var found = std.StringHashMap(Dir).init(self.allocator);
            defer found.deinit();
            for (self.sections) |*section| {
                const name = std.mem.sliceTo(&section.filename, 0);
                section.offset = offset;

                const length: u64 = if (LiteralFile.find(literal_files, name)) |lf|
                    lf.content.len
                else blk: {
                    for (froms) |from| {
                        const f = from.openFile(name, .{}) catch |err| {
                            if (err == File.OpenError.FileNotFound) {
                                continue;
                            }
                            log.debug("[payload] fail at openFile({s}) ({any})", .{ section.filename, err });
                            return error.FileOpenErr;
                        };
                        defer f.close();
                        try found.put(name, from);
                        const stat = try f.stat();
                        break :blk stat.size;
                    }
                    log.debug("[payload] not found {s} anywhere", .{section.filename});
                    return error.FileNotFound;
                };
                section.length = @intCast(length);

                offset += upAlign(OffsetT, section.length, self.core.align32);
            }

            if (config.prefix_header) {
                try payload.seekTo(self.core.length);
            }

            var digest = Digest.init(self.core.digest_type);
            var multiWriter = std.io.multiWriter(.{ digest.writer(), payload.writer() });
            const stream = multiWriter.writer();

            for (self.sections, 0..) |*section, i| {
                const name = std.mem.sliceTo(&section.filename, 0);
                const literal_file = LiteralFile.find(literal_files, name);
                if (literal_file) |lf| {
                    var fbs = std.io.fixedBufferStream(lf.content);
                    _ = try streamCopy(fbs.reader().any(), stream.any(), config.chunk, section.length, self.allocator);
                } else {
                    const f = try (found.get(name).?).openFile(name, .{});
                    defer f.close();
                    const actual = try streamCopy(f.reader().any(), stream.any(), config.chunk, section.length, self.allocator);
                    if (actual != section.length) return error.FileSizeChanged;
                }

                const padding_size = upAlign(OffsetT, section.length, self.core.align32) - section.length;
                if (padding_size != 0) {
                    try stream.writeByteNTimes(self.padding[0], padding_size);
                }

                var buffer: [256]u8 = undefined;
                log.debug(
                    "[payload] pack sections[{d}] {x:0>8} bytes from {s}",
                    .{ i, section.length, if (literal_file) |lf|
                        try std.fmt.bufPrint(&buffer, "command argument about {s}", .{lf.name})
                    else
                        try (found.get(name).?).realpath(name, &buffer) },
                );
            }

            digest.final(&self.core.digest);
            self.chksum.* = Chksum_F(self.inner[0 .. self.core.length - @sizeOf(Chksum_T)]);
            self.unpackable = true;
            self.print();

            if (header) |h| {
                try h.writeAll(self.inner);
                log.debug("[header] complete to write", .{});
            }

            if (config.prefix_header) {
                try payload.seekTo(0);
                try payload.writeAll(self.inner);
                log.debug("[payload] prefix header", .{});
            }
            log.debug("[payload] complete to pack", .{});
        }
        pub fn unpack(
            self: *const Self,
            payload: File,
            to: Dir,
            config: struct { save_header: ?File = null, chunk: usize = 4096 },
        ) !void {
            if (!self.unpackable) {
                return error.Unsupported;
            }
            if (config.save_header) |h| {
                try h.writeAll(self.inner);
                log.debug("[header] complete to write", .{});
            }

            var digest = Digest.init(self.core.digest_type);

            for (self.sections, 0..) |*section, i| {
                const name = std.mem.sliceTo(&section.filename, 0);
                const f = try to.createFile(name, .{});
                defer f.close();

                var multiWriter = std.io.multiWriter(.{ digest.writer(), f.writer() });
                const stream = multiWriter.writer();
                const actual = try streamCopy(payload.reader().any(), stream.any(), config.chunk, section.length, self.allocator);
                if (actual != section.length) return error.EndOfStream;

                const padding_size = upAlign(OffsetT, section.length, self.core.align32) - section.length;
                const skip = try streamCopy(payload.reader().any(), digest.writer().any(), config.chunk, padding_size, self.allocator);
                if (skip != padding_size) return error.EndOfStream;

                var buffer: [256]u8 = undefined;
                log.debug("[payload] unpack sections[{d}] {x:0>8} bytes to {s}", .{ i, actual, try to.realpath(name, &buffer) });
            }
            log.debug("[payload] complete to unpack", .{});

            if (!try digest.finalCheck(&self.core.digest, self.allocator)) {
                log.warn("[payload] digest mismatch", .{});
            }
        }
    };
}

test "Packer from" {
    const JSON_STR: []const u8 =
        \\ [
        \\   {
        \\     "filename": "file0",
        \\     "attr1": 6
        \\   },
        \\   {
        \\     "filename": "file1"
        \\   }
        \\ ] 
    ;
    const section = Section.new()
        .field("attr1", u32, .{ .default = 9 })
        .field("attr2", []const u8, .{ .default = "bye", .length = 10 });
    const SimplePacker = Packer(
        0x6679_7985,
        1,
        section,
        32,
        true,
        u32,
        crc32zlib_compute,
    );
    var packer = try SimplePacker.from_json_str(JSON_STR, testing.allocator);
    defer packer.destory();
    const core = packer.core;
    try testing.expect(core.magic == 0x6679_7985);
    try testing.expect(core.version == 1);
    try testing.expect(core.section_num == 2);
    try testing.expectEqualDeep(section.Core(32, true){
        .filename = initArray(u8, "file0", 32),
        .attr1 = 6,
        .attr2 = initArray(u8, "bye", 10),
    }, packer.sections[0]);

    var BS = std.io.fixedBufferStream(packer.inner);
    var BadBS = std.io.fixedBufferStream(packer.inner[0 .. packer.inner.len - 5]);

    try testing.expectError(error.CHKSUM_MISMATCH, SimplePacker.from_header_bin(BS.reader().any(), testing.allocator));
    try testing.expectError(error.EndOfStream, SimplePacker.from_header_bin(BadBS.reader().any(), testing.allocator));

    try testing.expectError(error.Unsupported, packer.unpack(BS.reader().any(), std.fs.cwd(), .{}));

    packer.chksum.* = (Crc32Zlib{}).compute(packer.inner[0 .. packer.core.length - @sizeOf(u32)]);
    BS.reset();
    var new_packer = try SimplePacker.from_header_bin(BS.reader().any(), testing.allocator);
    defer new_packer.destory();
    try testing.expectEqualDeep(section.Core(32, true){
        .filename = initArray(u8, "file1", 32),
        .attr1 = 9,
        .attr2 = initArray(u8, "bye", 10),
    }, new_packer.sections[1]);
}
