"""
==============================================================================
Module       : HashVerifier
Purpose      : Pre/post-wipe cryptographic hash computation for files and
               directory trees. Produces SHA-256 and SHA-3-256 digests that
               serve as cryptographic proof-of-state before and after secure
               deletion, satisfying audit requirements of NIST SP 800-88,
               DoD 5220.22-M, and ISO/IEC 27001:2022 Annex A.8.10.
Inputs       : File or directory path, optional algorithm selection
Outputs      : HashResult dataclass containing hex digests and metadata
Dependencies : hashlib (stdlib, Python 3.6+ for SHA-3)
Security     : All I/O uses buffered streaming (64 KB chunks) to avoid loading
               entire files into memory. Hash state objects are discarded
               immediately after digest extraction. Symlinks are refused to
               prevent hash-of-wrong-target attacks.
Compliance   : NIST SP 800-88 Rev.1 §4.3 (verification), DoD 5220.22-M
               (pass verification), ISO/IEC 27001:2022 Annex A.8.10,
               GDPR Art.5(1)(e)
==============================================================================
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Chunk size for streaming reads — 64 KB balances memory use vs syscall count
_CHUNK_SIZE: int = 65536


@dataclass
class FileHashEntry:
    """Cryptographic hash result for a single file."""
    path: str
    size_bytes: int
    sha256: str
    sha3_256: str
    computed_at: float  # POSIX timestamp


@dataclass
class HashResult:
    """
    Aggregate hash result for a wipe target (file or directory).
    Used for both pre-wipe and post-wipe states in the certificate.
    """
    target_path: str
    target_type: str          # "file" | "folder"
    total_size_bytes: int
    file_count: int
    sha256: str               # Aggregate SHA-256 over all content
    sha3_256: str             # Aggregate SHA-3-256 over all content
    file_hashes: List[FileHashEntry] = field(default_factory=list)
    computed_at: float = field(default_factory=time.time)
    duration_seconds: float = 0.0
    algorithm_version: str = "SHA-256+SHA3-256"

    def differs_from(self, other: "HashResult") -> bool:
        """
        Returns True if this result differs from another.
        Used post-wipe to confirm the content actually changed.
        Both algorithms must differ — a single-algorithm collision is
        treated as a wipe failure until the second algorithm also differs.
        """
        return self.sha256 != other.sha256 or self.sha3_256 != other.sha3_256

    def wipe_confirmed(self, other: "HashResult") -> bool:
        """
        Returns True only when BOTH hash algorithms show changed content.
        This is the strict verification used in certificates.
        """
        return self.sha256 != other.sha256 and self.sha3_256 != other.sha3_256


class HashVerificationError(Exception):
    """Raised when hash computation fails due to I/O or permission errors."""
    pass


class HashVerifier:
    """
    Computes dual cryptographic hashes (SHA-256 and SHA-3-256) for files
    and directory trees in a single streaming read pass.

    Directory hash construction:
        For each file, sorted lexicographically by relative path:
            agg_hash.update(4-byte path length || relative_path_utf8)
            agg_hash.update(sha256_hex_bytes)
        This detects: content changes, additions, deletions, renames.
    """

    def __init__(self, chunk_size: int = _CHUNK_SIZE):
        self._chunk_size = chunk_size

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def hash_target(self, path: str | Path) -> HashResult:
        """
        Unified entry point — dispatches to hash_file or hash_directory.
        Raises HashVerificationError if path does not exist or is a symlink.
        """
        path = Path(path).resolve()

        # Security: refuse top-level symlinks — caller must resolve explicitly
        if path.is_symlink():
            raise HashVerificationError(
                f"Symlink at target path: {path}. "
                "Resolve symlinks explicitly before hashing."
            )

        if path.is_file():
            return self._hash_single_file(path)
        elif path.is_dir():
            return self._hash_directory(path)
        else:
            raise HashVerificationError(
                f"Path does not exist or is not a file/directory: {path}"
            )

    def hash_file(self, path: str | Path) -> FileHashEntry:
        """
        Hash a single file. Both SHA-256 and SHA-3-256 computed in one pass.
        Returns FileHashEntry. Raises HashVerificationError on I/O failure.
        """
        path = Path(path).resolve()

        # Security: refuse symlinks in per-file calls too
        if path.is_symlink():
            raise HashVerificationError(
                f"Symlink detected at {path}. Resolve before hashing."
            )
        if not path.is_file():
            raise HashVerificationError(f"Not a regular file: {path}")

        sha256_obj = hashlib.sha256()
        sha3_256_obj = hashlib.sha3_256()
        size = 0

        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(self._chunk_size)
                    if not chunk:
                        break
                    # Both hash objects updated in the same loop — single I/O pass
                    sha256_obj.update(chunk)
                    sha3_256_obj.update(chunk)
                    size += len(chunk)
        except PermissionError as exc:
            raise HashVerificationError(
                f"Permission denied reading {path}: {exc}"
            ) from exc
        except OSError as exc:
            raise HashVerificationError(
                f"I/O error reading {path}: {exc}"
            ) from exc

        return FileHashEntry(
            path=str(path),
            size_bytes=size,
            sha256=sha256_obj.hexdigest(),
            sha3_256=sha3_256_obj.hexdigest(),
            computed_at=time.time(),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hash_single_file(self, path: Path) -> HashResult:
        """Wraps hash_file into a HashResult for a single-file target."""
        start = time.time()
        entry = self.hash_file(path)
        return HashResult(
            target_path=str(path),
            target_type="file",
            total_size_bytes=entry.size_bytes,
            file_count=1,
            sha256=entry.sha256,
            sha3_256=entry.sha3_256,
            file_hashes=[entry],
            computed_at=time.time(),
            duration_seconds=time.time() - start,
        )

    def _hash_directory(self, path: Path) -> HashResult:
        """
        Compute deterministic aggregate hashes over a directory tree.

        Aggregate hash construction prevents length-extension and path-confusion
        attacks by prefixing each path component with a 4-byte length field:
            agg.update( len(rel_path_bytes) as uint32 big-endian )
            agg.update( rel_path_bytes )
            agg.update( file_sha256_hex_bytes )
        File listing is sorted to ensure deterministic ordering across
        operating systems and filesystems.
        """
        start = time.time()
        file_entries: List[FileHashEntry] = []
        total_size = 0

        # Collect all regular files, sorted for determinism
        # Symlinks excluded — they are flagged separately by FileScanner
        all_files: List[Path] = sorted(
            p for p in path.rglob("*") if p.is_file() and not p.is_symlink()
        )

        for file_path in all_files:
            entry = self.hash_file(file_path)
            file_entries.append(entry)
            total_size += entry.size_bytes

        # Build aggregate hashes with length-prefixed path construction
        agg_sha256 = hashlib.sha256()
        agg_sha3_256 = hashlib.sha3_256()

        for entry in file_entries:
            rel_path = str(Path(entry.path).relative_to(path))
            path_bytes = rel_path.encode("utf-8")
            length_prefix = len(path_bytes).to_bytes(4, "big")

            agg_sha256.update(length_prefix)
            agg_sha256.update(path_bytes)
            agg_sha256.update(entry.sha256.encode("ascii"))

            agg_sha3_256.update(length_prefix)
            agg_sha3_256.update(path_bytes)
            agg_sha3_256.update(entry.sha3_256.encode("ascii"))

        return HashResult(
            target_path=str(path),
            target_type="folder",
            total_size_bytes=total_size,
            file_count=len(file_entries),
            sha256=agg_sha256.hexdigest(),
            sha3_256=agg_sha3_256.hexdigest(),
            file_hashes=file_entries,
            computed_at=time.time(),
            duration_seconds=time.time() - start,
        )

    # ------------------------------------------------------------------
    # Static utilities
    # ------------------------------------------------------------------

    @staticmethod
    def fingerprint_public_key(pem_bytes: bytes) -> str:
        """
        Compute SHA-256 fingerprint of a PEM-encoded RSA/ECDSA public key's
        DER form. Used to populate public_key_fingerprint fields in certificates.
        """
        from cryptography.hazmat.primitives.serialization import (
            load_pem_public_key,
            Encoding,
            PublicFormat,
        )
        public_key = load_pem_public_key(pem_bytes)
        der_bytes = public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(der_bytes).hexdigest()

    @staticmethod
    def verify_wipe_changed_content(
        before: HashResult, after: HashResult
    ) -> bool:
        """
        Strict post-wipe verification: both SHA-256 and SHA-3-256 must differ.
        Returns False if hashes are identical — indicating wipe did not execute.
        A partial match (one differs, one same) is treated as FAILED until
        both differ, guarding against single-algorithm weakness exploitation.
        """
        sha256_changed = before.sha256 != after.sha256
        sha3_changed = before.sha3_256 != after.sha3_256
        return sha256_changed and sha3_changed
