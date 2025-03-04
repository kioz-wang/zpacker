# filepacker

A tool to pack&unpack some files according to a `config.json`.

Powered by [zargs v0.13.0](https://github.com/kioz-wang/zargs/releases/tag/v0.13.0)

## usage

Show help message by execute `path/to/filepacker -h`

### pack

```bash
$ zig-out/bin/filepacker pack --cfg ./example/config.json --from ./test/ -o ./test/f.bin
info(packer): Magic 66797985 Version 1 Length 84 SectionNum 2
info(packer): Sections[0] 00000000,00000002 file0
debug(packer):   attr1 6
debug(packer):   attr2 bye
info(packer): Sections[1] 00000002,00000002 file1
debug(packer):   attr1 6
debug(packer):   attr2 bye
debug(packer): Chksum is e4722bfc
debug(packer): [payload] prefix header
debug(packer): [payload] pack sections[0]
debug(packer): [payload] pack sections[1]
debug(packer): [payload] complete to pack
Success to pack
```

### unpack

```bash
$ zig-out/bin/filepacker unpack -i test/f.bin 
info(packer): Magic 66797985 Version 1 Length 84 SectionNum 2
info(packer): Sections[0] 00000000,00000002 file0
debug(packer):   attr1 6
debug(packer):   attr2 bye
info(packer): Sections[1] 00000002,00000002 file1
debug(packer):   attr1 6
debug(packer):   attr2 bye
debug(packer): Chksum is e4722bfc
debug(packer): [header] complete to write
debug(packer): [payload] unpack sections[0]
debug(packer): [payload] unpack sections[1]
debug(packer): [payload] complete to unpack
Success to unpack
```

### show

```bash
$ zig-out/bin/filepacker show -i test/f.bin 
info(packer): Magic 66797985 Version 1 Length 84 SectionNum 2
info(packer): Sections[0] 00000000,00000002 file0
debug(packer):   attr1 6
debug(packer):   attr2 bye
info(packer): Sections[1] 00000002,00000002 file1
debug(packer):   attr1 6
debug(packer):   attr2 bye
debug(packer): Chksum is e4722bfc
Success to show
```
