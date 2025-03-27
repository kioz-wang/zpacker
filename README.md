# filepacker

A tool to (un)package files according to a `config.json`.

Powered by [zargs v0.14.4](https://github.com/kioz-wang/zargs/releases/tag/v0.14.4)

## usage

Show help message by execute `path/to/filepacker -h`

### pack

```bash
$ ./zig-out/bin/filepacker pack --from ./test/ --payload ./test/payload.bin ./example/config.json 
info(packer): Magic 66797985 Version 1 Length 84 SectionNum 2
info(packer): Sections[0] 00000000,00000006 file0
info(packer):   attr1 6
info(packer):   attr2 bye
info(packer): Sections[1] 00000006,00000004 file1
info(packer):   attr1 6
info(packer):   attr2 bye
info(packer): Chksum is 77de2313
debug(packer): [payload] prefix header
debug(packer): [payload] pack sections[0] 00000006 bytes from /home/kioz/devel/ziglearning/filepacker/test/file0
debug(packer): [payload] pack sections[1] 00000004 bytes from /home/kioz/devel/ziglearning/filepacker/test/file1
debug(packer): [payload] complete to pack
info: Success pack
```

### unpack

```bash
$ ./zig-out/bin/filepacker unpack --to test/out/ --save_header ./test/out/header.bin ./test/payload.bin 
debug(packer): [header] complete to write
debug(packer): [payload] unpack sections[0] 00000006 bytes to /home/kioz/devel/ziglearning/filepacker/test/out/file0
debug(packer): [payload] unpack sections[1] 00000004 bytes to /home/kioz/devel/ziglearning/filepacker/test/out/file1
debug(packer): [payload] complete to unpack
info: Success unpack
```

### show

```bash
$ ./zig-out/bin/filepacker show ./test/payload.bin 
info(packer): Magic 66797985 Version 1 Length 84 SectionNum 2
info(packer): Sections[0] 00000000,00000006 file0
info(packer):   attr1 6
info(packer):   attr2 bye
info(packer): Sections[1] 00000006,00000004 file1
info(packer):   attr1 6
info(packer):   attr2 bye
info(packer): Chksum is 77de2313
info: Success show
```
