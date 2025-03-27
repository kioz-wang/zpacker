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

pub const Section = struct {
    json_exts: []const StructField = &.{},
    core_exts: []const StructField = &.{},
    pub fn ext(self: *@This(), name: [:0]const u8, T: type, config: struct {
        default: ?T = null,
        length: usize = 0,
    }) *@This() {
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
        self.json_exts = self.json_exts ++ [_]StructField{.{
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
        self.core_exts = self.core_exts ++ [_]StructField{.{
            .alignment = @alignOf(CoreT),
            .default_value_ptr = core_default,
            .is_comptime = false,
            .name = name,
            .type = CoreT,
        }};
        return self;
    }
    pub fn Json(self: @This()) type {
        const Simple = struct {
            filename: []const u8,
        };
        var s = @typeInfo(Simple).@"struct";
        s.fields = s.fields ++ self.json_exts;
        return @Type(.{ .@"struct" = s });
    }
    pub fn Core(self: @This(), FN_MAXSIZE: comptime_int) type {
        const Simple = extern struct {
            filename: [FN_MAXSIZE]u8 = std.mem.zeroes([FN_MAXSIZE]u8),
            offset: u32 = 0,
            length: u32 = 0,
        };
        var s = @typeInfo(Simple).@"struct";
        s.fields = s.fields ++ self.core_exts;
        return @Type(.{ .@"struct" = s });
    }
    pub fn json2core(JsonT: type, CoreT: type, json: *const JsonT) CoreT {
        var core = CoreT{};
        inline for (@typeInfo(JsonT).@"struct".fields) |field| {
            if (field.type == []const u8) {
                @memcpy(@field(core, field.name)[0..@field(json, field.name).len], @field(json, field.name));
            } else {
                @field(core, field.name) = @field(json, field.name);
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
    comptime var section: Section = .{};
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
    comptime var section: Section = .{};
    _ = section.ext("attr1", []const u8, .{ .length = 6 }).ext("attr2", u32, .{ .default = 9 }).ext("attr3", []const u8, .{ .default = "bye", .length = 10 });
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
    comptime var section: Section = .{};
    const parsed = try std.json.parseFromSlice(section.Json(), testing.allocator, JSON_STR, .{});
    defer parsed.deinit();
    var core_section = Section.json2core(section.Json(), section.Core(5), &parsed.value);
    core_section.length = 1;
    const CORE = section.Core(5){ .filename = initArray(u8, "file0", 5), .length = 1 };
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
    comptime var section: Section = .{};
    _ = section.ext("attr1", []const u8, .{ .length = 6 }).ext("attr2", u32, .{ .default = 9 }).ext("attr3", []const u8, .{ .default = "bye", .length = 10 });
    const parsed = try std.json.parseFromSlice(section.Json(), testing.allocator, JSON_STR, .{});
    defer parsed.deinit();
    const json_section = parsed.value;
    try testing.expectEqualStrings("file0", json_section.filename);
    var core_section = Section.json2core(section.Json(), section.Core(32), &json_section);
    core_section.length = 1;
    const CORE = section.Core(32){
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
const AnyReader = std.io.AnyReader;
const AnyWriter = std.io.AnyWriter;

fn streamCopy(from: AnyReader, to: AnyWriter, chunk: usize, max_bytes: ?usize, allocator: std.mem.Allocator) !usize {
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

pub fn Packer(
    MAGIC: comptime_int,
    VERSION: comptime_int,
    Section_T: struct { Json: type, Core: type },
    Chksum_T: type,
    Chksum_F: fn ([]const u8) Chksum_T,
) type {
    const Core = extern struct {
        magic: u32 = MAGIC,
        version: u32 = VERSION,
        length: u32 = undefined,
        section_num: u32 = undefined,
    };
    return struct {
        core: *align(1) Core = undefined,
        sections: [*]align(1) Section_T.Core = undefined,
        chksum: *align(1) Chksum_T = undefined,
        _inner: []u8 = undefined,
        allocator: Allocator,
        unpackable: bool = false,
        pub fn from_json_str(json_str: []const u8, allocator: Allocator) !@This() {
            const parsed = try std.json.parseFromSlice([]Section_T.Json, allocator, json_str, .{});
            defer parsed.deinit();
            const json_sections = parsed.value;

            var packer = @This(){ .allocator = allocator };
            const length = @sizeOf(Core) + @sizeOf(Section_T.Core) * json_sections.len + @sizeOf(Chksum_T);
            packer._inner = try allocator.alloc(u8, length);
            @memset(packer._inner, 0);
            packer.core = @ptrCast(packer._inner);
            packer.sections = @ptrCast(&packer._inner[@sizeOf(Core)]);
            packer.chksum = @ptrCast(&packer._inner[length - @sizeOf(Chksum_T)]);

            const core = packer.core;
            core.magic = MAGIC;
            core.version = VERSION;
            core.length = @truncate(length);
            core.section_num = @truncate(json_sections.len);

            for (0..json_sections.len) |i| {
                packer.sections[i] = Section.json2core(Section_T.Json, Section_T.Core, &json_sections[i]);
            }
            return packer;
        }
        pub fn from_header_bin(header: AnyReader, allocator: Allocator) !@This() {
            const core = try header.readStruct(Core);
            if (core.magic != MAGIC) {
                log.debug("Magic Mismatch, expect {x} but {x}", .{ MAGIC, core.magic });
                return error.MAGIC_MISMATCH;
            }
            if (core.version != VERSION) {
                log.debug("Version Mismatch, expect {x} but {x}", .{ VERSION, core.version });
                return error.VERSION_MISMATCH;
            }

            var packer = @This(){ .allocator = allocator, .unpackable = true };
            packer._inner = try allocator.alloc(u8, core.length);
            errdefer allocator.free(packer._inner);
            packer.core = @ptrCast(packer._inner);
            packer.sections = @ptrCast(&packer._inner[@sizeOf(Core)]);
            packer.chksum = @ptrCast(&packer._inner[core.length - @sizeOf(Chksum_T)]);

            packer.core.* = core;
            if (try header.readAll(packer._inner[@sizeOf(Core)..]) != core.length - @sizeOf(Core)) {
                return error.EndOfStream;
            }
            const chksum = Chksum_F(packer._inner[0 .. core.length - @sizeOf(Chksum_T)]);
            if (packer.chksum.* != chksum) {
                log.debug("Chksum Mismatch, expect {x} but {x}", .{ packer.chksum.*, chksum });
                return error.CHKSUM_MISMATCH;
            }
            return packer;
        }
        pub fn destory(self: *const @This()) void {
            self.allocator.free(self._inner);
        }
        pub fn print(self: *const @This()) void {
            const core = self.core;
            log.info("Magic {x:0>8} Version {d} Length {d} SectionNum {d}", .{
                core.magic,
                core.version,
                core.length,
                core.section_num,
            });
            for (0..core.section_num) |i| {
                const section = &self.sections[i];
                log.info("Sections[{d}] {x:0>8},{x:0>8} {s}", .{ i, section.offset, section.length, section.filename });
                inline for (@typeInfo(Section_T.Core).@"struct".fields) |field| {
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
            log.info("Chksum is {x:0>8}", .{self.chksum.*});
        }
        pub fn pack(
            self: *@This(),
            from: Dir,
            header: ?AnyWriter,
            payload: ?AnyWriter,
            config: struct { prefix_header: bool = false, align_: u32 = 1, pad_byte: struct { u8, u8 } = .{ 0xf1, 0xe2 }, chunk: usize = 4096 },
        ) !void {
            var offset: u32 = 0;
            for (0..self.core.section_num) |i| {
                const section = &self.sections[i];
                const f = from.openFile(std.mem.sliceTo(&section.filename, 0), .{}) catch |err| {
                    @panic(try std.fmt.allocPrint(self.allocator, "fail at openFile({s}) ({any})", .{ section.filename, err }));
                };
                defer f.close();
                const stat = try f.stat();
                section.offset = offset;
                section.length = @truncate(stat.size);
                offset += section.length;
                offset = upAlign(u32, offset, config.align_);
            }
            self.chksum.* = Chksum_F(self._inner[0 .. self.core.length - @sizeOf(Chksum_T)]);
            self.unpackable = true;
            self.print();
            if (header) |h| {
                try h.writeAll(self._inner);
                log.debug("[header] complete to write", .{});
            }
            if (payload) |p| {
                if (config.prefix_header) {
                    try p.writeAll(self._inner);
                    log.debug("[payload] prefix header", .{});
                }
                var last_section: ?*align(1) Section_T.Core = null;
                for (0..self.core.section_num) |i| {
                    const section = &self.sections[i];
                    if (last_section) |last| {
                        try p.writeByteNTimes(config.pad_byte[1], section.offset - last.offset - last.length);
                    } else if (config.prefix_header) {
                        try p.writeByteNTimes(config.pad_byte[0], upAlign(u32, self.core.length, config.align_) - self.core.length);
                    }
                    last_section = section;

                    const sub_path = std.mem.sliceTo(&section.filename, 0);
                    const f = try from.openFile(sub_path, .{});
                    defer f.close();

                    const actual = try streamCopy(f.reader().any(), p, config.chunk, section.length, self.allocator);
                    if (actual != section.length) return error.FileSizeChanged;

                    var buffer: [256]u8 = undefined;
                    log.debug("[payload] pack sections[{d}] {x:0>8} bytes from {s}", .{ i, actual, try from.realpath(sub_path, &buffer) });
                }
                log.debug("[payload] complete to pack", .{});
            }
        }
        pub fn unpack(
            self: *const @This(),
            payload: AnyReader,
            to: Dir,
            config: struct { save_header: ?AnyWriter = null, chunk: usize = 4096 },
        ) !void {
            if (!self.unpackable) {
                return error.Unsupported;
            }
            if (config.save_header) |h| {
                try h.writeAll(self._inner);
                log.debug("[header] complete to write", .{});
            }
            var last_section: ?*align(1) Section_T.Core = null;
            for (0..self.core.section_num) |i| {
                const section = &self.sections[i];
                if (last_section) |last| {
                    try payload.skipBytes(section.offset - last.offset - last.length, .{});
                }
                last_section = section;

                const sub_path = std.mem.sliceTo(&section.filename, 0);
                const f = try to.createFile(sub_path, .{});
                defer f.close();

                const actual = try streamCopy(payload, f.writer().any(), config.chunk, section.length, self.allocator);
                if (actual != section.length) return error.EndOfStream;

                var buffer: [256]u8 = undefined;
                log.debug("[payload] unpack sections[{d}] {x:0>8} bytes to {s}", .{ i, actual, try to.realpath(sub_path, &buffer) });
            }
            log.debug("[payload] complete to unpack", .{});
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
    comptime var section: Section = .{};
    _ = section.ext("attr1", u32, .{ .default = 9 }).ext("attr2", []const u8, .{ .default = "bye", .length = 10 });
    const SimplePacker = Packer(
        0x6679_7985,
        1,
        .{ .Json = section.Json(), .Core = section.Core(32) },
        u32,
        crc32zlib_compute,
    );
    var packer = try SimplePacker.from_json_str(JSON_STR, testing.allocator);
    defer packer.destory();
    const core = packer.core;
    try testing.expect(core.magic == 0x6679_7985);
    try testing.expect(core.version == 1);
    try testing.expect(core.section_num == 2);
    try testing.expectEqualDeep(section.Core(32){
        .filename = initArray(u8, "file0", 32),
        .attr1 = 6,
        .attr2 = initArray(u8, "bye", 10),
    }, packer.sections[0]);

    var BS = std.io.fixedBufferStream(packer._inner);
    var BadBS = std.io.fixedBufferStream(packer._inner[0 .. packer._inner.len - 5]);

    try testing.expectError(error.CHKSUM_MISMATCH, SimplePacker.from_header_bin(BS.reader().any(), testing.allocator));
    try testing.expectError(error.EndOfStream, SimplePacker.from_header_bin(BadBS.reader().any(), testing.allocator));

    try testing.expectError(error.Unsupported, packer.unpack(BS.reader().any(), std.fs.cwd(), .{}));

    packer.chksum.* = (Crc32Zlib{}).compute(packer._inner[0 .. packer.core.length - @sizeOf(u32)]);
    BS.reset();
    var new_packer = try SimplePacker.from_header_bin(BS.reader().any(), testing.allocator);
    defer new_packer.destory();
    try testing.expectEqualDeep(section.Core(32){
        .filename = initArray(u8, "file1", 32),
        .attr1 = 9,
        .attr2 = initArray(u8, "bye", 10),
    }, new_packer.sections[1]);
}
