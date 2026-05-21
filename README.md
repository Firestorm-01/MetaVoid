MetaVoid  — Full Capability List

Formats Supported
PDF, JPEG, PNG, TIFF, WebP, GIF, BMP

What Gets Stripped
PDF: Author, Title, Subject, Keywords, Creator, Producer, CreationDate, ModDate, XMP streams (catalog + every object in the pool), PieceInfo (Illustrator/InDesign blobs), MarkInfo, EmbeddedFiles, OutputIntents, SpiderInfo, AssociatedFiles
Images: EXIF (all tags — GPS, camera make/model, lens, timestamps, artist, copyright), IPTC, XMP, ICC profiles, thumbnails, software tags, JPEG progressive marker, PNG text chunks (tEXt/iTXt/zTXt)

Safety Guarantees

Originals never touched unless --overwrite explicitly passed
Atomic writes via temp file + os.replace() on same filesystem
Symlinks never followed (path traversal prevention)
File type verified by magic bytes, not extension
Temp files always cleaned up on crash or failure
No network calls, no shell/subprocess, no eval




Pixel-level numpy re-encode for images (nuclear option — zero metadata survives)
Deep XMP sweep across all PDF objects, not just catalog
PDF embedded file and PieceInfo/MarkInfo removal
SHA-256 chain-of-custody ledger (--ledger)
Filename anonymisation with --rename (replaces name with 32-char random hex)
Encrypted PDF support (--password)
Bounded parallel processing (--workers N, max 16)
EXIF orientation preserved in pixel data after stripping


CLI Flags
--out-dir — custom output directory
--overwrite — strip in-place
--suffix — output filename suffix (default: _clean)
--recursive — recurse into subdirectories
--verify — re-read output and assert zero metadata remains
--report — full before/after metadata diff
--ledger — write .ledger.json with SHA-256 hashes
--rename — anonymise output filename
--password — password for encrypted PDFs
--workers — parallel threads (default: 4)
example commands:
python strip_metadata.py photo.jpg --verify --report --ledger
python strip_metadata.py document.pdf --verify --report --ledger

python strip_metadata.py document.pdf --verify --report --ledger
python strip_metadata.py photo.jpg --verify --report --ledger
--dry-run — preview without writing files
--quiet — suppress per-file output
--debug — full tracebacks and debug logging
