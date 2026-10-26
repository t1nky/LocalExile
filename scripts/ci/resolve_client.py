"""Re-resolve the native control bridge's client symbols in a client executable, offline (standard library only).

    python -I scripts/ci/resolve_client.py PathOfExile.exe                    # report only
    python -I scripts/ci/resolve_client.py PathOfExile.exe --write --version 3.29.4.1 --report report.md
    python -I scripts/ci/resolve_client.py Client/Game.patched.exe --check    # every signature unique, at its pinned VA
    python -I scripts/ci/resolve_client.py Client/Game.exe --check --mode xref

scripts/dev/client-signatures.json holds everything the bridge (scripts/dev/client-control.js) knows about the
client: per symbol a pinned image VA with its expected bytes, a wildcarded signature (`??` for bytes a patch moves)
with captures of the operands the bridge reads (call targets, RIP-relative globals, struct offsets), and optional
caller/string cross-references; per global and struct offset a pinned value and the capture it is derived from.
This script reads the executable in place (mmap, no copy) and resolves every symbol the way the bridge does at attach:

1. pinned: the expected bytes are still at the pinned VA;
2. signature: the pattern occurs exactly once (anchors marked `inside:<symbol>` are searched inside that function);
3. xref: the call target captured in a resolved caller, or the one function that references a unique string;
4. otherwise unresolved.

Then it recomputes the pinned VAs, expected bytes, globals and derived offsets. `--write` stores them (and the
executable's SHA-256 and build label, plus `--version`) back into the JSON; `--report` writes a markdown table.
Exit status: 0 nothing changed, 1 updated and everything resolved, 2 something is unresolved (what could be
resolved is still written). `--check` instead verifies that every symbol resolves by signature (`--mode xref`:
by cross-reference where one exists) to exactly its pinned VA, with unchanged globals and offsets (exit 0/1).
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
SIGNATURES = ROOT / "scripts" / "dev" / "client-signatures.json"
EXECUTE = 0x20000000
INSIDE_WINDOW = 0x4000  # bytes searched after the parent function's start for an `inside:` anchor
# lea r64, [rip+disp32]: REX.W (48/4C), 8D, ModRM with mod=00 rm=101.
LEA_RIP = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")


class Image:
    """A PE32+ executable read in place (bytes, bytearray or a read-only mmap; never copied). Addresses are RVAs,
    translated to file offsets through the section table; .pdata is searched lazily."""

    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not a PE file (no MZ header)")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE file (no PE signature)")
        count = struct.unpack_from("<H", data, pe + 6)[0]
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        optional = pe + 24
        if struct.unpack_from("<H", data, optional)[0] != 0x20B:
            raise ValueError("not a PE32+ (64-bit) image")
        self.base = struct.unpack_from("<Q", data, optional + 24)[0]
        directories = struct.unpack_from("<I", data, optional + 108)[0]
        exception = struct.unpack_from("<II", data, optional + 112 + 8 * 3) if directories > 3 else (0, 0)
        self.sections = []  # (name, rva, size present in the file, file offset, characteristics)
        table = optional + optional_size
        for i in range(count):
            name, vsize, rva, raw_size, raw = struct.unpack_from("<8sIIII", data, table + 40 * i)
            characteristics = struct.unpack_from("<I", data, table + 40 * i + 36)[0]
            size = max(0, min(raw_size, vsize or raw_size, len(data) - raw))
            self.sections.append((name.rstrip(b"\0").decode("ascii", "replace"), rva, size, raw, characteristics))
        self.pdata = None
        if exception[0] and exception[1] and self.offset(exception[0], exception[1]) is not None:
            self.pdata = (self.offset(exception[0], exception[1]), exception[1] // 12)

    @classmethod
    def open(cls, path):
        with open(path, "rb") as file:
            return cls(mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ))

    def offset(self, rva, size=1):
        """File offset of [rva, rva+size), or None if that is not all in one section's file data."""
        for _, start, length, raw, _ in self.sections:
            if start <= rva and rva + size <= start + length:
                return raw + rva - start
        return None

    def read(self, rva, size):
        at = self.offset(rva, size)
        return None if at is None else bytes(self.data[at:at + size])

    def code_ranges(self):
        return [(rva, size) for _, rva, size, _, flags in self.sections if flags & EXECUTE]

    def data_ranges(self):
        return [(rva, size) for _, rva, size, _, flags in self.sections if not flags & EXECUTE]

    def function(self, rva):
        """(begin, end) of the primary function containing rva, following chained unwind info; None if unknown."""
        if self.pdata is None:
            return None
        at, count = self.pdata
        low, high, found = 0, count - 1, -1
        while low <= high:  # binary search over the RUNTIME_FUNCTION table (sorted by begin)
            middle = (low + high) // 2
            if struct.unpack_from("<I", self.data, at + 12 * middle)[0] <= rva:
                found, low = middle, middle + 1
            else:
                high = middle - 1
        if found < 0:
            return None
        begin, end, unwind = struct.unpack_from("<III", self.data, at + 12 * found)
        if rva >= end:
            return None
        for _ in range(32):
            info = self.read(unwind, 4)
            if info is None:
                return None
            if not info[0] >> 3 & 4:  # UNW_FLAG_CHAININFO: the primary RUNTIME_FUNCTION follows the unwind codes
                return begin, end
            chained = self.read(unwind + 4 + 2 * ((info[2] + 1) & ~1), 12)
            if chained is None:
                return None
            begin, end, unwind = struct.unpack("<III", chained)
        return None

    def build_label(self):
        return build_label(self.data)


class Pattern:
    """A signature: hex bytes and `??` wildcards. Searched by its longest literal run (C-speed find), then verified."""
    cache = {}

    def __new__(cls, text):
        if text not in cls.cache:
            tokens = text.split()
            if not tokens or any(t != "??" and not re.fullmatch(r"[0-9a-fA-F]{2}", t) for t in tokens):
                raise ValueError(f"invalid pattern: {text!r}")
            self = super().__new__(cls)
            self.length = len(tokens)
            self.regex = re.compile(b"".join(b"." if t == "??" else re.escape(bytes.fromhex(t)) for t in tokens), re.S)
            runs = re.finditer(r"(?:[0-9a-fA-F]{2} ?)+", text + " ")
            best = max(runs, key=lambda m: len(m.group().split()), default=None)
            self.anchor_at = len(text[:best.start()].split()) if best else 0
            self.anchor = bytes.fromhex(best.group().replace(" ", "")) if best else b""
            cls.cache[text] = self
        return cls.cache[text]

    def at(self, data, offset):
        return offset >= 0 and self.regex.fullmatch(data, offset, offset + self.length) is not None

    def find(self, data, start, end):
        """File offsets of every match inside [start, end)."""
        if not self.anchor:
            return [m.start() for m in self.regex.finditer(data, start, end)]
        found, position = [], start + self.anchor_at
        while (hit := data.find(self.anchor, position, end)) >= 0:
            if hit - self.anchor_at + self.length <= end and self.at(data, hit - self.anchor_at):
                found.append(hit - self.anchor_at)
            position = hit + 1
        return found


def compile_pattern(pattern):
    compiled = Pattern(pattern)
    return compiled.regex, compiled.length


def matches_at(image, rva, pattern):
    compiled = Pattern(pattern)
    at = image.offset(rva, compiled.length)
    return at is not None and compiled.at(image.data, at)


def scan(image, pattern, ranges):
    """RVAs of the pattern's matches in the given (rva, size) ranges."""
    compiled, found = Pattern(pattern), []
    for rva, size in ranges:
        for _, start, length, raw, _ in image.sections:
            low, high = max(rva, start), min(rva + size, start + length)
            if low < high:
                found += [start + at - raw for at in compiled.find(image.data, raw + low - start, raw + high - start)]
    return found


def string_refs(image, text):
    """The function that references a unique NUL-terminated ASCII string with lea reg, [rip+disp32]."""
    needle = text.encode("ascii") + b"\0"
    hits = []
    for _, start, length, raw, flags in image.sections:
        if flags & EXECUTE:
            continue
        position = raw
        while (at := image.data.find(needle, position, raw + length)) >= 0:
            if at == raw or image.data[at - 1] == 0:
                hits.append(start + at - raw)
            position = at + 1
    if len(hits) != 1:
        return None, f"string found {len(hits)} times"
    functions = set()
    for _, start, length, raw, flags in image.sections:
        if not flags & EXECUTE:
            continue
        for match in LEA_RIP.finditer(image.data, raw, raw + length - 7):
            at = match.start()
            if start + at - raw + 7 + struct.unpack_from("<i", image.data, at + 3)[0] == hits[0]:
                functions.add(image.function(start + at - raw))
    if len(functions) != 1 or None in functions:
        return None, f"string referenced from {len(functions)} functions"
    return functions.pop()[0], "string reference"


def capture_value(image, start, capture):
    at, size, kind = capture["at"], capture["size"], capture["kind"]
    raw = image.read(start + at, size)
    if kind in ("rip", "rel32"):
        return image.base + start + capture.get("end", at + size) + int.from_bytes(raw, "little", signed=True)
    return int.from_bytes(raw, "little", signed=kind == "disp")


def parse_int(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def resolve(signatures, image, mode="pinned"):
    """{symbols, globals, offsets} with, per entry, rva/value, method (pinned/signature/xref/string/constant/
    unresolved) and detail. mode: pinned (normal), signature (skip pinned), xref (also prefer cross-references)."""
    pinned_base = parse_int(signatures["client"]["imageBase"])
    specs = signatures["symbols"]
    symbols = {}

    def location_ok(name, start):
        check = specs[name].get("start")
        if not check or image.pdata is None:
            return True, ""
        if check == "function":
            function = image.function(start)
            return (function is not None and function[0] == start), "not a function start"
        if check.startswith("inside:"):
            parent = symbols.get(check[7:])
            if not parent or parent["rva"] is None:
                return True, f"{check[7:]} unresolved; not checked"
            mine, theirs = image.function(start), image.function(parent["start"])
            return (mine is not None and mine == theirs), f"not inside {check[7:]}"
        raise ValueError(f"{name}: unknown start check {check!r}")

    def accept(name, start, method, detail=""):
        spec = specs[name]
        ok, why = location_ok(name, start)
        if not ok:
            return False, why
        captures = {}
        if matches_at(image, start, spec["pattern"]):
            captures = {cap: capture_value(image, start, c) for cap, c in spec.get("captures", {}).items()}
        elif method in ("signature", "pinned"):
            return False, "pattern mismatch"
        else:
            detail = (detail + "; " if detail else "") + "pattern differs here, captures unavailable"
        if why and why.endswith("not checked"):
            detail = (detail + "; " if detail else "") + why
        symbols[name] = {"rva": start + spec.get("offset", 0), "start": start, "method": method,
                         "detail": detail, "captures": captures}
        return True, ""

    def has_xref(name):
        return bool(specs[name].get("callers") or specs[name].get("string"))

    def try_pinned(name):
        spec = specs[name]
        start = parse_int(spec["va"]) - pinned_base - spec.get("offset", 0)
        expected = bytes.fromhex(spec["bytes"])
        if start < 0 or image.read(start, len(expected)) != expected:
            return False, "pinned bytes differ"
        return accept(name, start, "pinned")

    def try_signature(name):
        spec = specs[name]
        check = spec.get("start", "")
        ranges = image.code_ranges()
        parent = symbols.get(check[7:]) if check.startswith("inside:") else None
        if parent and parent["rva"] is not None:
            # A function's chained fragments usually follow it; location_ok() checks the match belongs to it.
            ranges = [(parent["start"], INSIDE_WINDOW)]
        found = scan(image, spec["pattern"], ranges)
        if len(found) != 1:
            return False, f"signature matched {len(found)} times"
        return accept(name, found[0], "signature")

    def try_xref(name):
        spec = specs[name]
        targets = {}
        for source in spec.get("callers", []):
            caller, cap = source.split(".")
            value = symbols.get(caller, {}).get("captures", {}).get(cap)
            if value is not None:
                targets.setdefault(value - image.base, []).append(caller)
        if len(targets) > 1:
            return False, "callers disagree: " + ", ".join(f"{image.base + t:#x}" for t in targets)
        if targets:
            (target, callers), = targets.items()
            return accept(name, target - spec.get("offset", 0), "xref", "call target in " + ", ".join(callers))
        if spec.get("string"):
            begin, why = string_refs(image, spec["string"])
            if begin is None:
                return False, why
            return accept(name, begin, "string", f"references \"{spec['string']}\"")
        return False, "no resolved caller"

    reasons = {name: [] for name in specs}
    deferred = []

    def note(name, why):
        if why and why not in reasons[name]:
            reasons[name].append(why)

    def parent_pending(name):
        check = specs[name].get("start", "")
        return check.startswith("inside:") and check[7:] not in symbols

    def follow():
        progress = True
        while progress:
            progress = False
            for name in specs:
                if name not in symbols and has_xref(name):
                    ok, why = try_xref(name)
                    progress |= ok
                    if not ok:
                        note(name, why)

    for name in specs:
        if mode == "pinned":
            ok, why = try_pinned(name)
            if ok:
                continue
            note(name, why)
        if (mode == "xref" and has_xref(name)) or parent_pending(name):
            deferred.append(name)
            continue
        ok, why = try_signature(name)
        if not ok:
            note(name, why)
    follow()
    # Signatures deferred for a cross-reference or for their parent function, then what they make reachable.
    for name in deferred:
        if name not in symbols:
            ok, why = try_signature(name)
            if not ok:
                note(name, why)
    follow()
    for name in specs:
        symbols.setdefault(name, {"rva": None, "start": None, "method": "unresolved",
                                  "detail": "; ".join(reasons[name]), "captures": {}})

    def source_values(sources):
        values, missing = {}, []
        for source in sources:
            name, cap = source.split(".")
            value = symbols[name]["captures"].get(cap)
            (missing.append(source) if value is None else values.setdefault(source, value))
        return values, missing

    globals_ = {}
    for name, spec in signatures.get("globals", {}).items():
        values, missing = source_values([spec["from"]])
        if values:
            (source, value), = values.items()
            globals_[name] = {"rva": value - image.base, "method": symbols[source.split(".")[0]]["method"],
                              "detail": f"from {source}"}
        else:
            globals_[name] = {"rva": None, "method": "unresolved", "detail": f"{spec['from']} unresolved"}
    offsets = {}
    for name, spec in signatures.get("offsets", {}).items():
        sources = spec.get("from", [])
        sources = [sources] if isinstance(sources, str) else sources
        values, missing = source_values(sources)
        adjusted = {source: value + spec.get("add", 0) for source, value in values.items()}
        distinct = sorted(set(adjusted.values()))
        if len(distinct) > 1:
            offsets[name] = {"value": None, "method": "unresolved",
                             "detail": "sources disagree: " + ", ".join(f"{s}={v:#x}" for s, v in adjusted.items())}
        elif distinct:
            first = next(iter(adjusted))
            offsets[name] = {"value": distinct[0], "method": symbols[first.split(".")[0]]["method"],
                             "detail": "from " + ", ".join(adjusted)}
        else:
            offsets[name] = {"value": parse_int(spec["value"]), "method": "constant",
                             "detail": ("sources unresolved: " + ", ".join(missing)) if sources else "pinned constant"}
    return {"symbols": symbols, "globals": globals_, "offsets": offsets}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build_label(data):
    """The client's own build label from its `/tags/<label>` version string (e.g. 3.29.3b); the executable has no
    version resource. `data` is the file or the mapped image."""
    match = re.search(rb"/tags/([0-9][0-9A-Za-z._-]{0,31})\0", data)
    return match.group(1).decode("ascii") if match else None


def updated(signatures, image, result, sha256, version=None):
    """A copy of the signatures with every resolved value recomputed for this image."""
    out = json.loads(json.dumps(signatures))
    out["client"].update(imageBase=f"{image.base:#x}", sha256=sha256, build=image.build_label() or "unknown")
    if version:
        out["client"]["version"] = version
    for name, spec in out["symbols"].items():
        found = result["symbols"][name]
        if found["rva"] is not None:
            spec["va"] = f"{image.base + found['rva']:#x}"
            length = len(spec["pattern"].split())
            spec["bytes"] = image.read(found["start"], length).hex()
    for name, spec in out.get("globals", {}).items():
        if result["globals"][name]["rva"] is not None:
            spec["va"] = f"{image.base + result['globals'][name]['rva']:#x}"
    for name, spec in out.get("offsets", {}).items():
        found = result["offsets"][name]
        if found["value"] is not None and found["method"] != "constant":
            spec["value"] = f"{found['value']:#x}"
    return out


def unresolved(result):
    names = [f"symbol {n}" for n, r in result["symbols"].items() if r["rva"] is None]
    names += [f"symbol {n} (pattern differs)" for n, r in result["symbols"].items()
              if r["rva"] is not None and "pattern differs" in r["detail"]]
    names += [f"global {n}" for n, r in result["globals"].items() if r["rva"] is None]
    names += [f"offset {n}" for n, r in result["offsets"].items()
              if r["value"] is None or r["detail"].startswith("sources unresolved")]
    return names


def report(old, new, result, path):
    base = parse_int(new["client"]["imageBase"])
    lines = [f"Client `{path.name}`: version {old['client'].get('version')} -> {new['client'].get('version')}, "
             f"build {new['client'].get('build')}, SHA-256 `{new['client']['sha256']}`.", ""]
    missing = unresolved(result)
    lines.append(f"**{len(missing)} unresolved:** " + ", ".join(missing) if missing else "Everything resolved.")
    lines += ["", "| symbol | old VA | new VA | method | status |", "|---|---|---|---|---|"]
    for name, found in result["symbols"].items():
        before = old["symbols"][name]["va"]
        after = f"{base + found['rva']:#x}" if found["rva"] is not None else "-"
        status = "unresolved" if found["rva"] is None else ("unchanged" if after == before else "moved")
        detail = f" ({found['detail']})" if found["detail"] else ""
        lines.append(f"| {name} | {before} | {after} | {found['method']}{detail} | {status} |")
    lines += ["", "| global | old VA | new VA | method | status |", "|---|---|---|---|---|"]
    for name, found in result["globals"].items():
        before = old["globals"][name]["va"]
        after = f"{base + found['rva']:#x}" if found["rva"] is not None else "-"
        status = "unresolved" if found["rva"] is None else ("unchanged" if after == before else "moved")
        lines.append(f"| {name} | {before} | {after} | {found['method']} ({found['detail']}) | {status} |")
    lines += ["", "| offset | old | new | method | status |", "|---|---|---|---|---|"]
    for name, found in result["offsets"].items():
        before = old["offsets"][name]["value"]
        after = f"{found['value']:#x}" if found["value"] is not None else "-"
        status = "unresolved" if found["value"] is None else \
            ("unverified" if found["detail"].startswith("sources unresolved") else
             "unchanged" if parse_int(after) == parse_int(before) else "changed")
        lines.append(f"| {name} | {before} | {after} | {found['method']} ({found['detail']}) | {status} |")
    return "\n".join(lines) + "\n"


def check(signatures, result):
    """Problems found when the result must reproduce every pinned value exactly."""
    base = parse_int(signatures["client"]["imageBase"])
    problems = []
    for name, found in result["symbols"].items():
        pinned = parse_int(signatures["symbols"][name]["va"])
        if found["rva"] is None:
            problems.append(f"{name}: unresolved ({found['detail']})")
        elif base + found["rva"] != pinned:
            problems.append(f"{name}: {found['method']} found {base + found['rva']:#x}, pinned {pinned:#x}")
        elif not found["captures"] and signatures["symbols"][name].get("captures"):
            problems.append(f"{name}: captures unavailable")
    for name, found in result["globals"].items():
        pinned = parse_int(signatures["globals"][name]["va"])
        if found["rva"] is None or base + found["rva"] != pinned:
            problems.append(f"global {name}: {found['detail']}")
    for name, found in result["offsets"].items():
        pinned = parse_int(signatures["offsets"][name]["value"])
        if found["value"] != pinned or found["detail"].startswith(("sources", "unresolved")):
            problems.append(f"offset {name}: {found['value']} vs pinned {pinned:#x} ({found['detail']})")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("exe", type=Path)
    parser.add_argument("--signatures", type=Path, default=SIGNATURES)
    parser.add_argument("--mode", choices=("pinned", "signature", "xref"), default=None,
                        help="resolution order (default: pinned; --check defaults to signature)")
    parser.add_argument("--write", action="store_true", help="store the recomputed values in the signatures file")
    parser.add_argument("--version", help="client patch version to record (e.g. 3.29.4.1)")
    parser.add_argument("--report", type=Path, help="write the markdown report here")
    parser.add_argument("--check", action="store_true", help="require every pinned value to be reproduced")
    options = parser.parse_args()
    signatures = json.loads(options.signatures.read_text(encoding="utf-8"))
    image = Image.open(options.exe)
    mode = options.mode or ("signature" if options.check else "pinned")
    result = resolve(signatures, image, mode)
    base = image.base
    if options.check:
        width = max(map(len, result["symbols"]))
        for name, found in result["symbols"].items():
            where = f"{base + found['rva']:#x}" if found["rva"] is not None else "-"
            print(f"{name:<{width}}  {where:>12}  {found['method']}{' (' + found['detail'] + ')' if found['detail'] else ''}")
        for name, found in result["globals"].items():
            where = f"{base + found['rva']:#x}" if found["rva"] is not None else "-"
            print(f"global {name}: {where} {found['method']} ({found['detail']})")
        for name, found in result["offsets"].items():
            value = f"{found['value']:#x}" if found["value"] is not None else "-"
            print(f"offset {name}: {value} {found['method']} ({found['detail']})")
        problems = check(signatures, result)
        print("\n".join(problems) if problems else
              f"OK: {len(result['symbols'])} symbols ({mode}), {len(result['globals'])} globals and "
              f"{len(result['offsets'])} offsets reproduce the pinned values in {options.exe.name}")
        return 1 if problems else 0
    sha256 = sha256_file(options.exe)  # streamed: hashing the mmap would keep all 79 MB resident
    new = updated(signatures, image, result, sha256, options.version)
    text = report(signatures, new, result, options.exe)
    if options.report:
        options.report.write_text(text, encoding="utf-8")
    print(text)
    if options.write:
        options.signatures.write_text(json.dumps(new, indent=2) + "\n", encoding="utf-8")
    if unresolved(result):
        return 2
    return 0 if new == signatures else 1


if __name__ == "__main__":
    sys.exit(main())
