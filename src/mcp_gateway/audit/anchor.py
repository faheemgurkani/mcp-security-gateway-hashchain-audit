"""Log-head anchor.

The anchor stores the (seq, mac) of the newest entry somewhere the agent
cannot write: in the lab, a volume owned by the gateway user in the tool
zone. Without it, cutting entries off the end of the log leaves a chain
that still verifies (truncation attack, A3).
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Head:
    seq: int
    mac: str


class FileAnchor:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)

    def write(self, head: Head) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w") as f:
            json.dump({"seq": head.seq, "mac": head.mac}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)  # atomic: readers never see a half-written head

    def read(self) -> Head | None:
        if not self.path.exists():
            return None
        data = json.loads(self.path.read_text())
        return Head(seq=int(data["seq"]), mac=str(data["mac"]))
