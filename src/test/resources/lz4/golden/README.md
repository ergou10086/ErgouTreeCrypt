Fixtures generated with the reference LZ4 CLI v1.9.4 (2026-10-04).

Commands: `lz4 -f payload.txt independent.lz4`, `lz4 -BD -B4`, `lz4 -BX`; concatenated.lz4 contains two independent frames. reference.tar.lz4 contains a deterministic PAX TAR with 目录/payload.txt and empty.bin.

Expected payload: payload.txt; concatenated output repeats it twice. Empty frame expands to zero bytes.
