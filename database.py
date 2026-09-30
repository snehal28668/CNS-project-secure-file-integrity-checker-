"""Local JSON persistence for file registrations and verification history."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class IntegrityDatabase:
    """Store file metadata, original hashes, and verification events in JSON."""

    def __init__(self, database_path: str | Path = "data/integrity_records.json") -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.database_path.exists():
            return {"files": {}, "verifications": []}
        try:
            with self.database_path.open("r", encoding="utf-8") as file_handle:
                loaded = json.load(file_handle)
            if not isinstance(loaded, dict):
                raise ValueError("Database root must be an object")
            loaded.setdefault("files", {})
            loaded.setdefault("verifications", [])
            return loaded
        except (OSError, json.JSONDecodeError, ValueError):
            return {"files": {}, "verifications": []}

    def _save(self) -> None:
        temporary_path = self.database_path.with_suffix(".tmp")
        with temporary_path.open("w", encoding="utf-8") as file_handle:
            json.dump(self.data, file_handle, indent=2)
        temporary_path.replace(self.database_path)

    @staticmethod
    def _timestamp() -> str:
        return datetime.now().astimezone().isoformat(timespec="seconds")

    def register_file(self, metadata: dict[str, Any], file_hash: str) -> None:
        """Create or update the original record for a file path."""
        path = str(Path(metadata["path"]).resolve())
        self.data["files"][path] = {
            "name": metadata["name"],
            "path": path,
            "size": metadata["size"],
            "type": metadata["type"],
            "hash": file_hash,
            "registered_at": self._timestamp(),
        }
        self._save()

    def get_record(self, file_path: str | Path) -> dict[str, Any] | None:
        return self.data["files"].get(str(Path(file_path).resolve()))

    def get_records(self) -> list[dict[str, Any]]:
        return sorted(self.data["files"].values(), key=lambda item: item.get("registered_at", ""), reverse=True)

    def add_verification(self, path: str, original_hash: str, current_hash: str, status: str) -> None:
        self.data["verifications"].insert(0, {
            "path": str(Path(path).resolve()),
            "name": Path(path).name,
            "original_hash": original_hash,
            "current_hash": current_hash,
            "status": status,
            "verified_at": self._timestamp(),
        })
        self.data["verifications"] = self.data["verifications"][:1000]
        self._save()

    def get_verifications(self) -> list[dict[str, Any]]:
        return list(self.data["verifications"])

    def clear_history(self) -> None:
        self.data["verifications"] = []
        self._save()

    def dashboard_stats(self) -> dict[str, Any]:
        verifications = self.get_verifications()
        return {
            "registered": len(self.data["files"]),
            "verified": sum(item["status"] == "verified" for item in verifications),
            "compromised": sum(item["status"] == "compromised" for item in verifications),
            "last_verification": verifications[0]["verified_at"] if verifications else "No verification yet",
        }
