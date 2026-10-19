"""Conservative, reviewable scope selection over canonical textual LLVM IR.

This is a direct-reference graph, not a semantic slicer or a data-encryption
pass. Only definitions in the supplied modules are owned/protectable. Unknown
edges are reported instead of pretending that the selected boundary is complete.
"""

from __future__ import annotations

import argparse
from collections import defaultdict, deque
import hashlib
import json
from pathlib import Path
import re


SYMBOL = r'@(?:"(?:[^"\\]|\\.)*"|[-A-Za-z$._0-9]+)'
TOKENS = re.compile(SYMBOL + r'|"(?:[^"\\]|\\.)*"')
IR_TOKENS = re.compile(r'[@%](?:"(?:[^"\\]|\\.)*"|[-A-Za-z$._0-9]+)|"(?:[^"\\]|\\.)*"')
CALL_TARGET = re.compile(r'(' + SYMBOL + r'|%(?:"(?:[^"\\]|\\.)*"|[-A-Za-z$._0-9]+))\s*\(')
GLOBAL_START = re.compile(r'^\s*(' + SYMBOL + r')\s*=')
IGNORED_INTRINSICS = ("llvm.dbg.", "llvm.lifetime.")
LIMITATIONS = [
    "Analysis covers only the supplied textual IR definitions, not the whole application; omitted translation units, libraries and callers remain outside the graph.",
    "Supported input is canonical LLVM textual IR with ordinary direct calls and named globals. This parser does not validate LLVM syntax or perform pointer, alias, taint, virtual-dispatch or semantic analysis.",
    "Inline assembly always requires review because hidden references cannot establish graph relevance. Operand bundles on presentation calls are not accepted as transparent forwarding.",
    "Public-presentation and public-global reasons are explicit human policy assertions, not a proof that UI code or observable behavior reveals no sensitive information.",
    "Function selection and subsequent virtualization do not encrypt referenced globals, constants, metadata or interfaces. Inline constants are not separately inventoried.",
    "A ready manifest means the supported structural checks passed, not that the chosen scope prevents reverse engineering or independently reproducing the behavior.",
]


def _name(token):
    value = token[1:]
    if value.startswith('"'):
        value = value[1:-1]
        value = re.sub(r"\\([0-9A-Fa-f]{2})", lambda match: chr(int(match[1], 16)), value)
    return value


def _symbols(text):
    return [_name(match[0]) for match in TOKENS.finditer(text) if match[0].startswith("@")]


def _mask_tokens(text, *, literals_only=False):
    """Hide strings/symbols from syntax checks while preserving offsets."""
    return IR_TOKENS.sub(lambda match: match[0] if literals_only and match[0][0] in "@%"
                        else " " * len(match[0]), text)


def _without_comment(line):
    quoted, escaped = False, False
    for offset, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == ";" and not quoted:
            return line[:offset]
    return line


def _issue(kind, symbol, detail, *, relevant=True):
    return {"kind": kind, "symbol": symbol, "detail": detail,
            "relevant": relevant, "severity": "review" if relevant else "limitation"}


def _parse_modules(ir_paths):
    functions, globals_, aliases, declarations, hashes, issues = {}, {}, {}, set(), {}, []
    for supplied in ir_paths:
        path = Path(supplied).resolve()
        try:
            data = path.read_bytes()
            hashes[str(path)] = hashlib.sha256(data).hexdigest()
            lines = [_without_comment(line).strip() for line in data.decode("utf-8-sig").splitlines()]
        except (OSError, UnicodeError) as exc:
            issues.append(_issue("input_error", str(path), str(exc)))
            continue
        index = 0
        while index < len(lines):
            line = lines[index]
            if line.startswith("define "):
                start, header = index + 1, line
                while not header.endswith("{") and index + 1 < len(lines):
                    if "}" in header or lines[index + 1].startswith(("define ", "declare ", "@")):
                        break
                    index += 1
                    header += " " + lines[index]
                names = _symbols(header)
                if not header.endswith("{") or not names:
                    issues.append(_issue("unsupported_definition", str(path), f"Cannot parse function header at line {start}; use canonical multiline LLVM IR."))
                    index += 1
                    continue
                name, body = names[0], []
                index += 1
                while index < len(lines) and lines[index] != "}":
                    body.append(lines[index])
                    index += 1
                if index >= len(lines):
                    issues.append(_issue("unterminated_definition", name, f"Missing closing brace in {path}:{start}"))
                if name in functions:
                    issues.append(_issue("duplicate_definition", name, "Duplicate names across modules are ambiguous; link/rename modules before analysis."))
                else:
                    functions[name] = {"header": header, "body": body, "path": str(path), "line": start}
            elif line.startswith("declare "):
                names = _symbols(line)
                if names:
                    declarations.add(names[0])
            elif GLOBAL_START.match(line):
                name = _name(GLOBAL_START.match(line)[1])
                initializer = line.split("=", 1)[1]
                # Canonical aggregate initializers can span lines. Top-level
                # declarations begin in column-independent recognizable forms.
                while index + 1 < len(lines) and lines[index + 1] and not re.match(
                        r'^(?:@|define\b|declare\b|attributes\b|!|\$|source_filename\b|target\b|module\b|uselistorder\b)', lines[index + 1]):
                    index += 1
                    initializer += " " + lines[index]
                entry = {"initializer": initializer, "references": set(_symbols(initializer)),
                         "defined": not bool(re.search(r"\bexternal\b", initializer)), "path": str(path)}
                if re.search(r"\b(?:alias|ifunc)\b", initializer):
                    aliases[name] = entry
                elif name in globals_:
                    issues.append(_issue("duplicate_global", name, "Duplicate globals across modules require a linked-module view."))
                else:
                    globals_[name] = entry
            elif line.startswith("module asm"):
                issues.append(_issue("module_assembly", str(path), "Module assembly can hide calls and data references."))
            index += 1
    return functions, globals_, aliases, declarations, hashes, issues


def _policy_names(policy, key, issues, *, required=False):
    value = policy.get(key, [])
    if isinstance(value, dict):
        value = list(value)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        issues.append(_issue("invalid_policy", key, "Expected a list of symbol names."))
        return set()
    if required and not value:
        issues.append(_issue("invalid_policy", key, "At least one core root is required."))
    return set(value)


def _policy_reasons(policy, key, issues):
    value = policy.get(key, {})
    if not isinstance(value, dict):
        issues.append(_issue("invalid_policy", key, "Expected symbol -> nonempty reviewed reason."))
        return {}
    result = {}
    for name, reason in value.items():
        if not isinstance(name, str) or not name or not isinstance(reason, str) or not reason.strip():
            issues.append(_issue("invalid_policy", str(name), f"{key} requires a nonempty reviewed reason."))
        else:
            result[name] = reason.strip()
    return result


def _argument_span_after_target(text):
    """Locate argument contents without matching calls inside string literals."""
    target = CALL_TARGET.search(_mask_tokens(text, literals_only=True))
    if not target:
        return None
    masked = _mask_tokens(text)
    start, depth, end = target.end(), 1, target.end()
    while end < len(text) and depth:
        depth += (masked[end] == "(") - (masked[end] == ")")
        end += 1
    if depth:
        return None
    return start, end - 1


def _arguments_after_target(text):
    """Extract ordinary named SSA arguments; constants/expressions return None."""
    span = _argument_span_after_target(text)
    if span is None:
        return None
    content = text[span[0]:span[1]]
    segments, segment, nesting = [], "", 0
    for char in content:
        if char == "," and nesting == 0:
            segments.append(segment.strip())
            segment = ""
        else:
            segment += char
            nesting += (char in "([{<") - (char in ")]}>" )
    if segment.strip():
        segments.append(segment.strip())
    values = []
    for segment in segments:
        match = re.search(r'(%(?:"(?:[^"\\]|\\.)*"|[-A-Za-z$._0-9]+))\s*$', segment)
        if not match:
            return None
        values.append(match[1])
    return values


def _forwarding_issues(function):
    instructions = [line for line in function["body"]
                    if line and not line.endswith(":") and not line.startswith("#dbg_")]
    call_lines, returns, issues = [], [], []
    for line in instructions:
        instruction = re.sub(r'^%[^=]+\s*=\s*', '', line)
        if re.match(r'^(?:(?:tail|musttail|notail)\s+)?call\b', instruction):
            call_lines.append(line)
        elif instruction.startswith("ret "):
            returns.append(instruction)
        else:
            issues.append("contains non-forwarding instruction: " + line)
    if len(call_lines) > 1:
        issues.append("multiple calls expose a sequence, not a single reviewed forwarding edge")
    if len(returns) != 1:
        issues.append("presentation boundary must have one ordinary return")
    if len(call_lines) == 1:
        span = _argument_span_after_target(call_lines[0])
        if span is not None and "[" in _mask_tokens(call_lines[0])[span[1] + 1:]:
            issues.append("call operand bundle or unsupported trailing aggregate is not transparent forwarding")
        params = _arguments_after_target(function["header"])
        arguments = _arguments_after_target(call_lines[0])
        if params is None or arguments is None or params != arguments:
            issues.append("call arguments are not the unchanged ordered boundary parameters (constant or transformed arguments need review)")
        result = re.match(r'^(%[^=\s]+)\s*=', call_lines[0])
        if len(returns) == 1:
            returned = re.search(r'(%[^,\s]+)\s*(?:,.*)?$', returns[0])
            if (result and (not returned or returned[1] != result[1])) or (not result and returns[0] != "ret void"):
                issues.append("return does not forward the call result unchanged")
    # A reviewed public leaf can return a literal tag or an unchanged parameter;
    # the policy assertion, not a semantic inference, classifies that as public.
    return issues


def analyze_scope(ir_paths, policy_dict, mode="expanded"):
    """Return a manifest; ``needs_review`` blocks automatic protection.

    Policy keys: core_roots, sensitive_functions, public_presentation (reason
    map), optional sensitive_globals/public_globals (reason map)/entry_points,
    and max_functions (default 64). entry_points only verifies symbol presence;
    it does not seed expansion or assert whole-application entry coverage. Core
    mode deliberately protects roots only; expanded mode also seeds explicit
    sensitive functions and expands neighbors.
    """
    if mode not in {"core", "expanded"}:
        raise ValueError("mode must be core or expanded")
    if isinstance(ir_paths, (str, Path)):
        ir_paths = [ir_paths]
    functions, globals_, aliases, declarations, hashes, unresolved = _parse_modules(list(ir_paths))
    if not hashes:
        unresolved.append(_issue("missing_input", "", "No readable input IR was supplied."))
    if not isinstance(policy_dict, dict):
        unresolved.append(_issue("invalid_policy", "", "Policy must be a JSON object."))
        policy_dict = {}
    supported_policy = {"core_roots", "sensitive_functions", "public_presentation", "sensitive_globals",
                        "public_globals", "entry_points", "max_functions", "schema_version", "description"}
    for key in sorted(set(policy_dict) - supported_policy):
        unresolved.append(_issue("unknown_policy_field", key, "Unknown policy field; refusing to silently ignore a possible misspelling."))
    roots = _policy_names(policy_dict, "core_roots", unresolved, required=True)
    sensitive = _policy_names(policy_dict, "sensitive_functions", unresolved)
    sensitive_globals = _policy_names(policy_dict, "sensitive_globals", unresolved)
    entries = _policy_names(policy_dict, "entry_points", unresolved)
    public = _policy_reasons(policy_dict, "public_presentation", unresolved)
    public_globals = _policy_reasons(policy_dict, "public_globals", unresolved)
    max_functions = policy_dict.get("max_functions", 64)
    if type(max_functions) is not int or max_functions < 1:
        unresolved.append(_issue("invalid_policy", "max_functions", "Expected a positive integer."))
        max_functions = 64
    for name in sorted(roots | sensitive | entries | set(public)):
        if name not in functions:
            unresolved.append(_issue("missing_policy_function", name, "Policy symbol has no owned definition in the supplied IR."))
    for name in sorted(sensitive_globals | set(public_globals)):
        if name not in globals_:
            unresolved.append(_issue("missing_policy_global", name, "Policy global is absent from the supplied IR."))

    calls, callers, function_globals, address_taken = {}, defaultdict(set), {}, []
    raw_issues = []
    for name, function in functions.items():
        direct, references = set(), set(_symbols("\n".join(function["body"])))
        if len(_symbols(function["header"])) > 1 or re.search(r"\b(?:personality|prefix|prologue)\b", function["header"]):
            raw_issues.append(("unsupported_header_dependency", name, "Function header has personality/prefix/prologue or additional symbol references."))
        for line in function["body"]:
            masked = _mask_tokens(line)
            operation = re.search(r"\b(call|invoke|callbr)\b", masked)
            direct_target = None
            if operation:
                if re.search(r"(?<![-A-Za-z$._0-9@%!])asm(?![-A-Za-z$._0-9])", masked[operation.end():]):
                    raw_issues.append(("inline_assembly", name, "Inline assembly can hide calls and data references; graph relevance cannot be established: " + line))
                else:
                    target = CALL_TARGET.search(_mask_tokens(line[operation.end():], literals_only=True))
                    if target and target[1].startswith("@"):
                        direct_target = _name(target[1])
                        direct.add(direct_target)
                    else:
                        raw_issues.append(("indirect_call", name, "Indirect or unsupported call expression: " + line))
            for referenced in set(_symbols(line)) & set(functions):
                # A function can occur once as callee and again as a callback.
                if referenced != direct_target or _symbols(line).count(referenced) > 1:
                    address_taken.append({"owner": name, "function": referenced, "kind": "instruction_reference"})
            for referenced in set(_symbols(line)) & declarations:
                if referenced != direct_target or _symbols(line).count(referenced) > 1:
                    raw_issues.append(("external_function_reference", name, referenced))
        calls[name] = direct
        for target in direct & set(functions):
            callers[target].add(name)
        function_globals[name] = references - set(functions) - declarations - set(aliases)
        for target in direct - set(functions):
            if target.startswith(IGNORED_INTRINSICS):
                raw_issues.append(("compiler_intrinsic", name, target))
            else:
                raw_issues.append(("alias_call" if target in aliases else "external_call", name, target))
        for alias in references & set(aliases):
            raw_issues.append(("alias_reference", name, alias))
    for name, global_ in {**globals_, **aliases}.items():
        for target in global_["references"] & set(functions):
            address_taken.append({"owner": name, "function": target, "kind": "global_or_alias_reference"})
        for target in sorted(global_["references"] & declarations):
            raw_issues.append(("external_function_reference", name,
                               f"{target}; referenced as data by global/alias {name}; callback behavior is not resolved."))

    global_dependencies = {name: data["references"] - set(functions) - declarations
                           for name, data in globals_.items()}
    for name, refs in function_globals.items():
        pending = list(refs)
        while pending:
            item = pending.pop()
            for dependency in global_dependencies.get(item, set()):
                if dependency not in refs:
                    refs.add(dependency)
                    pending.append(dependency)
    consumers = defaultdict(set)
    for name, refs in function_globals.items():
        for ref in refs:
            consumers[ref].add(name)

    effective_boundaries = set(public) - roots - sensitive
    expanded, expanded_reasons, reached_boundaries = set(), defaultdict(set), set()
    queue = deque()
    for name in sorted((roots | sensitive) & set(functions)):
        expanded.add(name)
        expanded_reasons[name].add("policy:core_root" if name in roots else "policy:sensitive_function")
        queue.append(name)
    while queue:
        current = queue.popleft()
        neighbors = defaultdict(set)
        for target in calls[current] & set(functions):
            neighbors[target].add(f"callee_of:{current}")
        for source in callers[current]:
            neighbors[source].add(f"caller_of:{current}")
        for global_ in function_globals[current]:
            for consumer in consumers[global_]:
                if consumer != current:
                    neighbors[consumer].add(f"shared_global:{global_}:with:{current}")
        for name, reasons in sorted(neighbors.items()):
            if name in effective_boundaries:
                reached_boundaries.add(name)
                continue
            expanded_reasons[name].update(reasons)
            if name not in expanded:
                expanded.add(name)
                queue.append(name)
    selected = (roots & set(functions)) if mode == "core" else expanded
    reasons = {name: (["policy:core_root"] if mode == "core" else sorted(expanded_reasons[name]))
               for name in sorted(selected)}
    if len(selected) > max_functions:
        unresolved.append(_issue("max_functions_exceeded", "", f"Selected {len(selected)} functions exceeds cap {max_functions}; selection was NOT truncated."))

    boundary_functions = {}
    for name, reason in sorted(public.items()):
        issues = []
        overridden = name in roots or name in sensitive
        if name in reached_boundaries:
            for ref in sorted(function_globals[name]):
                if ref in sensitive_globals or ref not in public_globals:
                    issues.append(f"references unreviewed or sensitive global:{ref}")
            for callee in sorted(calls[name] & set(functions)):
                if callee not in expanded and callee not in effective_boundaries:
                    issues.append(f"calls unprotected helper:{callee}")
                elif callee in effective_boundaries:
                    issues.append(f"calls another presentation boundary:{callee}; review the boundary chain explicitly")
            # Even a call+ret wrapper can inject a hidden literal argument.
            issues.extend(_forwarding_issues(functions[name]))
            if issues:
                unresolved.append(_issue("presentation_boundary", name, "; ".join(issues)))
        boundary_functions[name] = {"reason": reason, "reviewed": bool(reason),
                                    "reached": name in reached_boundaries,
                                    "overridden_by_sensitive_or_core": overridden,
                                    "issues": issues}

    data_risks = []
    for name in sorted(selected):
        for global_ in sorted(function_globals[name]):
            if global_ not in public_globals or global_ in sensitive_globals:
                data_risks.append({"function": name, "global": global_,
                                   "kind": "global_data_not_protected_by_function_selection",
                                   "detail": "Referenced data needs a separate protection/review decision; no data encryption is claimed."})
    relevant_global_owners = {ref for owner in selected | reached_boundaries for ref in function_globals[owner]}
    for kind, owner, detail in raw_issues:
        # Assembly can hide the very edge that would make its owner reachable.
        relevant = (kind == "inline_assembly" or owner in selected
                    or owner in reached_boundaries or owner in relevant_global_owners)
        if kind == "compiler_intrinsic":
            relevant = False
        unresolved.append(_issue(kind, owner, detail, relevant=relevant))
    for item in address_taken:
        # function_globals already includes transitive global dependencies. A
        # public table label does not review the bodies of callback targets.
        relevant = (item["function"] in selected or item["owner"] in selected
                    or item["owner"] in reached_boundaries or item["owner"] in relevant_global_owners)
        unresolved.append(_issue("address_taken_function", item["function"],
                                 f"Referenced as data by {item['owner']} ({item['kind']}); callback targets/callers are not resolved.", relevant=relevant))
    for name in aliases:
        unresolved.append(_issue("alias_definition", name, "Aliases/ifunc dispatch are not resolved by this parser.",
                                 relevant=any(name in function_globals[function] for function in selected)))
    limitations = list(LIMITATIONS)
    if entries:
        limitations.append("entry_points is a symbol-presence check only; it does not seed selection or establish coverage of actual runtime entry points.")
    if mode == "core":
        limitations.append("Core-only mode intentionally leaves declared sensitive and inferred neighboring functions unprotected for comparison; it is not an expanded-scope protection claim.")
    return {"schema_version": 1, "status": "needs_review" if data_risks or any(item["relevant"] for item in unresolved) else "ready",
            "mode": mode, "selected_functions": sorted(selected), "reasons": reasons,
            "neighborhood_reasons": {name: sorted(values) for name, values in sorted(expanded_reasons.items())},
            "boundary_functions": boundary_functions,
            "deliberately_unselected_neighbors": sorted(expanded - selected),
            "unselected_sensitive_functions": sorted((sensitive & set(functions)) - selected),
            "globals": {name: {"defined": globals_.get(name, {}).get("defined", False),
                                "consumers": sorted(consumers[name]),
                                "referenced_globals": sorted(global_dependencies.get(name, set())),
                                "public_reason": public_globals.get(name), "sensitive": name in sensitive_globals}
                        for name in sorted(set(globals_) | set(consumers))},
            "data_risks": data_risks,
            "graph": {"calls": {name: sorted(targets) for name, targets in sorted(calls.items())},
                      "callers": {name: sorted(callers[name]) for name in sorted(functions)},
                      "function_globals": {name: sorted(refs) for name, refs in sorted(function_globals.items())},
                      "shared_globals": {name: sorted(users) for name, users in sorted(consumers.items()) if len(users) > 1},
                      "address_taken": address_taken},
            "unresolved": unresolved, "limitations": limitations, "input_hashes": hashes,
            "policy": policy_dict, "max_functions": max_functions,
            "declared_entry_points": sorted(entries),
            "entry_point_semantics": "Symbol-presence validation only; core_roots, sensitive_functions and supported graph edges determine selection.",
            "owned_definitions": sorted(functions)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ir", action="append", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--mode", choices=("core", "expanded"), default="expanded")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        policy = json.loads(args.policy.read_text(encoding="utf-8-sig"))
        manifest = analyze_scope(args.ir, policy, args.mode)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{manifest['status']}: {len(manifest['selected_functions'])} functions; {args.output}")
    return 0 if manifest["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
