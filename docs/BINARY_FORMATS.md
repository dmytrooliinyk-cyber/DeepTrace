# Binary formats

Binary parsing begins with three rules: decide byte order, validate the complete field range, and interpret bit fields only after the containing integer is known.

## PE

The two-byte `MZ` signature begins the DOS header. The four-byte little-endian value at offset `0x3c`, named `e_lfanew`, points to the later `PE\0\0` signature. This indirection exists because PE retained a DOS-compatible prefix.

DeepTrace reads the COFF machine, section count, timestamp, optional-header size, entry point, image base, and section table. Section flags are reduced to R, W, and X memory permissions. Entropy is calculated over available raw section data.

High entropy can come from compression, encryption, packed code, or ordinary data. A writable and executable section can be legitimate. These are indicators for investigation, not malware verdicts.

## ELF

The ELF identification bytes select 32-bit or 64-bit layouts and little or big byte order. The remaining header is unpacked with the selected format. DeepTrace reports ABI, file type, machine, entry point, table offsets, entry sizes, and counts. It does not yet walk program or section headers.

## General file inspection

Magic signatures identify several common formats independently of extensions. SHA-256 is the primary content identifier. MD5 is included only for matching artifacts in systems that still publish MD5 values. Shannon entropy ranges from 0 bits per byte for a constant byte stream toward 8 for a uniform distribution.

