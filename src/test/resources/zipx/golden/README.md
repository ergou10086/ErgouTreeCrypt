# Independent ZIPX fixtures

Regenerate with `python scripts/generate_zipx_fixtures.py --sevenzip PATH_TO_7ZA`.
The checked-in corpus was generated with Python 3.12 and official 7-Zip 23.01.
All content is synthetic text created for these tests; no user media is included.
`SHA256SUMS` records the precise fixture bytes.

Python `zipfile` independently produces Store, Deflate, BZip2 and ZIP LZMA,
with forced ZIP64 local records and both seekable and streaming data descriptors.
Python `lzma` produces ZIP method 95 (XZ). Python `cryptography` and `hashlib`
produce XZ entries with AE-1/AE-2 AES-128/192/256, including the 10-byte HMAC-SHA1
authentication code. 7-Zip independently produces Deflate64, BZip2 and LZMA,
each plain and AES-256 encrypted. Its two PPMd fixtures are explicit unsupported
method regression cases, not claims of PPMd support.

These fixtures are read by desktop JUnit, the shared Gradle JVM suite and Android
ART instrumentation. No production Java writer is involved in their construction.

Primary references:

- [PKWARE ZIP APPNOTE 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [WinZip ZIPX explanation](https://kb.winzip.com/en/130326)
- [WinZip AES specification](https://www.winzip.com/en/support/aes-encryption/)
- [7-Zip official downloads](https://www.7-zip.org/download.html)
