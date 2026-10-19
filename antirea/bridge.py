"""Target-scoped MCP tools for an attacker without general filesystem access.

Run as an absolute script so neither attacker cwd nor PYTHONPATH is relied upon.
Only the defender configuration can select the binary. No tool accepts a path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def schema(properties=None, required=None):
    return {"type": "object", "properties": properties or {},
            "required": required or [], "additionalProperties": False}


STR = {"type": "string"}
PAGE_CHARS = 24_000
INLINE_CHARS = 60_000
MAX_CACHE_CHARS = 4_000_000
COMPUTE_HELP = (
    "compute requires BOTH code and pairs. Example: "
    '{"code":"def solve(x, y):\\n    return [x + y, hex(x)]\\n","pairs":[[2,3]]}. '
    "For one-off work use pairs=[[0,0]] and ignore x,y. "
    "Define solve(x,y); helpers and literal top-level tables are allowed. "
    "Computed initialization belongs inside a function. Return JSON data (convert bytes to list). "
    "No imports, attributes/methods, comprehensions, keyword arguments, or I/O. "
    "Use indexed assignment instead of list.append."
)


def normalize_public_context(value):
    """Accept explicit public text, never a path, artifact loader, or source map."""
    if value is None:
        return {"kind": "none", "description": "No public context provided."}
    if not isinstance(value, dict) or set(value) - {"kind", "description", "title"}:
        raise ValueError("public_context permits only kind, description, and optional title text; no file paths or artifacts")
    if value.get("kind") not in {"cli_text", "none"}:
        raise ValueError("public_context kind must be cli_text or none; this adapter does not load GUI/screenshots")
    if type(value.get("description")) is not str or not value["description"]:
        raise ValueError("public_context description must be nonempty text")
    if "title" in value and type(value["title"]) is not str:
        raise ValueError("public_context title must be text")
    normalized = {key: value[key] for key in ("kind", "description", "title") if key in value}
    if len(json.dumps(normalized, ensure_ascii=False).encode("utf-8")) > 65_536:
        raise ValueError("public_context exceeds the 64KB public-text limit")
    return normalized


def public_context_hash(value=None):
    normalized = normalize_public_context(value)
    encoded = json.dumps(normalized, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


ENGINE_SOURCES = {
    "opcodes": "include/kagura/VMOpcodes.def",
    "interpreter": "runtime/core/vm_interpreter.c",
    "vm-format": "include/kagura/VM.h",
    "lowering": "lib/Transforms/VM/VMObfuscation.cpp",
    "fla": "lib/Transforms/CFG/ControlFlowFlattening.cpp",
    "sub": "lib/Transforms/Data/Substitution.cpp",
    "co": "lib/Transforms/Data/ConstantObfuscation.cpp",
    "selection": "lib/Transforms/Utils.cpp",
    "selection-header": "include/kagura/Utils.h",
    "config": "lib/Transforms/Infrastructure/ConfigLoader.cpp",
    "pass-registry": "include/kagura/PassRegistry.def",
}
TOOLS = [
    {"name": "public_context", "description": "Read the explicitly provided public CLI interface/presentation text. Identical for every comparison arm; no private source, policy, hidden tests, file lookup, GUI or screenshots. Takes no arguments.",
     "inputSchema": schema()},
    {"name": "procedures", "description": "REA/Ghidra discovered functions. Optional substring filter, offset, limit.",
     "inputSchema": schema({"query": STR, "offset": {"type": "integer", "minimum": 0}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}})},
    {"name": "decompile", "description": "REA/Ghidra C-like pseudocode for a function name or address.",
     "inputSchema": schema({"procedure": STR}, ["procedure"])},
    {"name": "disassemble", "description": "REA/Ghidra native assembly for a function name or address.",
     "inputSchema": schema({"procedure": STR}, ["procedure"])},
    {"name": "strings", "description": "REA/Ghidra strings from the target binary; optional substring filter.",
     "inputSchema": schema({"query": STR})},
    {"name": "read_bytes", "description": "REA bytes at a target virtual address (hex address, maximum 4096 bytes).",
     "inputSchema": schema({"address": STR, "length": {"type": "integer", "minimum": 1, "maximum": 4096}}, ["address", "length"])},
    {"name": "references", "description": "REA cross-references to a target virtual address.",
     "inputSchema": schema({"address": STR}, ["address"])},
    {"name": "query", "description": "Run the target on at most 32 chosen input pairs; total query budget is enforced.",
     "inputSchema": schema({"pairs": {"type": "array", "minItems": 1, "maxItems": 32,
        "items": {"type": "array", "minItems": 2, "maxItems": 2,
                  "items": {"type": "integer", "minimum": 0, "maximum": 4294967295}}}}, ["pairs"])},
    {"name": "engine_source", "description": "Public Kagura engine source, never target source. Use to interpret VM bytecode.",
     "inputSchema": schema({"file": {"type": "string", "enum": list(ENGINE_SOURCES)}}, ["file"])},
    {"name": "fetch_page", "description": "Read the next page of a cached full tool response. Concatenate text chunks in offset order to reconstruct its serialized JSON. Tokens access only responses already returned in this session, never files.",
     "inputSchema": schema({"token": STR, "offset": {"type": "integer", "minimum": 0}}, ["token", "offset"])},
    {"name": "compute", "description": "Run attacker-supplied pure Python solve(x,y) on 1..32 chosen uint32 pairs; return bounded JSON values. No filesystem/network/target/hidden-test access. Limits: 5s, 256MiB, 64KB JSON output; no target queries consumed. " + COMPUTE_HELP,
     "inputSchema": schema({"code": STR, "pairs": {"type": "array", "minItems": 1, "maxItems": 32,
        "items": {"type": "array", "minItems": 2, "maxItems": 2,
                  "items": {"type": "integer", "minimum": 0, "maximum": 4294967295}}}}, ["code", "pairs"])},
]


class Bridge:
    def __init__(self, config):
        self.root = Path(config["root"])
        self.binary = Path(config["binary"])
        self.log_dir = Path(config["log_dir"])
        self.query_limit = config["query_limit"]
        self.queried = 0
        self.calls = 0
        self.session = None
        self.pages = {}
        self.cached_chars = 0
        self.deadline_epoch = config.get("deadline_epoch")
        self.public_context_data = normalize_public_context(config.get("public_context"))

    def close(self):
        if self.session:
            self.session.__exit__(None, None, None)

    def rea(self, name, args):
        from antirea.rea import ReaSession
        if self.session is None:
            self.session = ReaSession(self.root, self.log_dir / "rea", timeout_s=300)
            self.session.__enter__()
            opened = self.session.open_binary(self.binary)
            if isinstance(opened, dict) and opened.get("isError"):
                raise RuntimeError(f"REA failed to import binary: {opened}")
        result = self.session.call(name, args)
        if result.get("isError"):
            raise RuntimeError(f"REA tool error: {result}")
        payload = ReaSession.result_payload(result)
        if isinstance(payload, dict) and "normalized_result" in payload:
            return {"result": payload["normalized_result"],
                    "limitations": payload.get("limitations", []), "evidence_id": payload.get("evidence_id")}
        return payload

    def execute(self, name, args):
        self.calls += 1
        if self.calls > 100:
            raise ValueError("Tool call budget exhausted (100 calls).")
        if name == "public_context":
            if args:
                raise ValueError("public_context takes no arguments and cannot read file paths")
            return dict(self.public_context_data)
        if name == "fetch_page":
            return self.fetch_page(args.get("token"), args.get("offset"))
        if name == "compute":
            from antirea.judge import scratch_compute
            if not isinstance(args.get("code"), str) or not isinstance(args.get("pairs"), list) or not args["pairs"]:
                return {"status": "rejected", "error": COMPUTE_HELP}
            computed = scratch_compute(args["code"], args["pairs"], timeout_seconds=5)
            if computed.get("status") != "passed":
                computed["help"] = COMPUTE_HELP
            return computed
        mapping = {"decompile": "procedure_pseudo_code", "disassemble": "procedure_assembly",
                   "references": "xrefs", "read_bytes": "read_bytes"}
        if name in mapping:
            clean = {key: args[key] for key in ("procedure", "address", "length") if key in args}
            if name == "read_bytes" and not 1 <= clean.get("length", 0) <= 4096:
                raise ValueError("length must be between 1 and 4096")
            if any(not isinstance(value, str) or len(value) > 256 for key, value in clean.items() if key != "length"):
                raise ValueError("Invalid procedure/address")
            return self.rea(mapping[name], clean)
        if name in {"procedures", "strings"}:
            payload = self.rea("list_procedures" if name == "procedures" else "list_strings", {})
            # Providers can wrap lists differently; preserve their structure when unknown.
            data = payload
            if isinstance(payload, dict):
                for key in ("procedures", "strings", "items", "results", "result", "normalized_result"):
                    if isinstance(payload.get(key), list):
                        data = payload[key]
                        break
            query = str(args.get("query", "")).lower()
            if isinstance(data, list):
                filtered = [row for row in data if query in json.dumps(row).lower()]
                offset = max(0, int(args.get("offset", 0)))
                limit = min(100, max(1, int(args.get("limit", 100))))
                return {"total": len(filtered), "offset": offset, "items": filtered[offset:offset + limit],
                        "limitations": payload.get("limitations", []) if isinstance(payload, dict) else []}
            if query:
                lines = json.dumps(data, indent=2).splitlines()
                return {"matching_lines": [line for line in lines if query in line.lower()]}
            return data
        if name == "query":
            pairs = args.get("pairs")
            if not isinstance(pairs, list) or not 1 <= len(pairs) <= 32:
                raise ValueError("Supply 1..32 input pairs.")
            if self.queried + len(pairs) > self.query_limit:
                raise ValueError("Black-box input budget exceeded.")
            for pair in pairs:
                if not isinstance(pair, list) or len(pair) != 2 or any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in pair):
                    raise ValueError("Inputs must be pairs of unsigned 32-bit integers.")
            self.queried += len(pairs)
            run = subprocess.run([str(self.binary)], input="".join(f"{x} {y}\n" for x, y in pairs),
                                 capture_output=True, text=True, timeout=5, check=True)
            values = [int(line) for line in run.stdout.splitlines()]
            if len(values) != len(pairs):
                raise RuntimeError("Target returned an unexpected number of outputs.")
            if any(not 0 <= value <= 0xFFFFFFFFFFFFFFFF for value in values):
                raise RuntimeError("Target returned a value outside unsigned 64-bit range.")
            return {"results": values, "queries_remaining": self.query_limit - self.queried}
        if name == "engine_source":
            if args.get("file") not in ENGINE_SOURCES:
                raise ValueError("Unknown engine source selection.")
            relative = ENGINE_SOURCES[args["file"]]
            return {"public_engine_file": relative, "source": (self.root / ".tools/kagura" / relative).read_text(encoding="utf-8")}
        raise ValueError("Unknown tool")

    def fetch_page(self, token, offset):
        if not isinstance(token, str) or token not in self.pages:
            raise ValueError("Unknown response token; file paths are not accepted.")
        cached = self.pages[token]
        text = cached["text"]
        if type(offset) is not int or not 0 <= offset < len(text):
            raise ValueError("Page offset must be inside the cached response.")
        end = min(offset + PAGE_CHARS, len(text))
        intervals = sorted(cached["delivered"] + [(offset, end)])
        merged = []
        for start, stop in intervals:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(stop, merged[-1][1]))
            else:
                merged.append((start, stop))
        cached["delivered"] = merged
        remaining = len(text) - sum(stop - start for start, stop in merged)
        return {"page": {"token": token, "offset": offset,
                         "next_offset": end if end < len(text) else None,
                         "total_chars": len(text), "undelivered_chars": remaining,
                         "evidence_complete": remaining == 0},
                "text": text[offset:end],
                "format": "Concatenate text chunks by offset, then parse JSON."}

    def _serialize_response(self, result, name):
        text = json.dumps(result, ensure_ascii=False)
        # This removes project path hints only; access control is the tool API.
        text = text.replace(str(self.root).replace("\\", "\\\\"), "<project>")
        if name != "fetch_page" and len(text) > INLINE_CHARS:
            if self.cached_chars + len(text) > MAX_CACHE_CHARS:
                raise ValueError("Full response exceeds session evidence-cache capacity; no text was silently truncated.")
            token = secrets.token_urlsafe(18)
            self.pages[token] = {"text": text, "delivered": []}
            self.cached_chars += len(text)
            result = self.fetch_page(token, 0)
            text = json.dumps(result, ensure_ascii=False)
        page = result.get("page") if isinstance(result, dict) else None
        return text, page

    def call(self, name, args):
        start = time.monotonic()
        rea = name in {"procedures", "decompile", "disassemble", "strings", "read_bytes", "references"}
        try:
            result = self.execute(name, args)
            error = name == "compute" and result.get("status") != "passed"
            text, page = self._serialize_response(result, name)
        except Exception as exc:
            result, error = {"error": f"{type(exc).__name__}: {exc}"}, True
            text, page = self._serialize_response(result, name)
        record = {"tool": name, "arguments": args, "rea": rea, "error": error,
                  "seconds": round(time.monotonic() - start, 3), "result": result}
        record["paginated"] = page is not None
        if page is not None:
            record.update({"page_token": page["token"], "page_offset": page["offset"],
                           "next_offset": page["next_offset"], "total_chars": page["total_chars"],
                           "undelivered_chars": page["undelivered_chars"],
                           "evidence_complete": page["evidence_complete"]})
        if isinstance(self.deadline_epoch, (int, float)):
            remaining = max(0, round(self.deadline_epoch - time.time(), 2))
            record["seconds_remaining"] = remaining
        with (self.log_dir / "bridge-audit.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps(record) + "\n")
        content = [{"type": "text", "text": text}]
        if "seconds_remaining" in record:
            content.append({"type": "text", "text": json.dumps({"seconds_remaining": record["seconds_remaining"]})})
        return {"content": content, "isError": error}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    config = json.loads(parser.parse_args().config.read_text(encoding="utf-8"))
    bridge = Bridge(config)
    try:
        for line in sys.stdin:
            try:
                request = json.loads(line)
                if "id" not in request:
                    continue
                method = request.get("method")
                if method == "initialize":
                    result = {"protocolVersion": request.get("params", {}).get("protocolVersion", "2024-11-05"),
                              "capabilities": {"tools": {}}, "serverInfo": {"name": "anti-rea-scoped", "version": "0.1.0"}}
                elif method == "tools/list":
                    result = {"tools": TOOLS}
                elif method == "tools/call":
                    params = request["params"]
                    result = bridge.call(params["name"], params.get("arguments", {}))
                elif method == "ping":
                    result = {}
                else:
                    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32601, "message": "Method not found"}}), flush=True)
                    continue
                print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
            except Exception as exc:
                print(f"bridge protocol error: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
    finally:
        bridge.close()


if __name__ == "__main__":
    main()
