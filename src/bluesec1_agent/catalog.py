"""Read what the runtime's tool catalog advertises, without hard-coding its contents.

The catalog is the source of truth for tool names, argument shapes and enums, and it may
change between the training arena and the final. These helpers resolve its JSON-schema
references generically: the search scope types (so the harness can infer a scope kind),
argument defaults (so cache keys ignore spelled-out defaults) and a compact summary that
keeps every name and enum but drops schema boilerplate from the agent's context.
"""

from typing import Any

_MAX_REF_HOPS = 20
_MAX_DEPTH = 12
_MAX_ARG_DESCRIPTION = 200
_SCALAR_TYPES = ("string", "integer", "number", "boolean")


def resolve(schema: Any, root: dict[str, Any]) -> Any:
    """Follow local `#/...` references inside one tool schema."""
    for _ in range(_MAX_REF_HOPS):
        if not (isinstance(schema, dict) and isinstance(schema.get("$ref"), str)):
            return schema
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            return schema
        node: Any = root
        for part in ref[2:].split("/"):
            node = node.get(part) if isinstance(node, dict) else None
        if node is None:
            return schema
        schema = node
    return schema


def alternatives(schema: Any, root: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the resolved alternatives of an anyOf / oneOf schema (the schema itself if none)."""
    schema = resolve(schema, root)
    if not isinstance(schema, dict):
        return []
    for key in ("anyOf", "oneOf"):
        if isinstance(schema.get(key), list):
            found: list[dict[str, Any]] = []
            for option in schema[key]:
                found.extend(alternatives(option, root))
            return found
    return [schema]


def _values(schema: Any, root: dict[str, Any]) -> list[Any]:
    schema = resolve(schema, root)
    if not isinstance(schema, dict):
        return []
    if "const" in schema:
        return [schema["const"]]
    enum = schema.get("enum")
    return list(enum) if isinstance(enum, list) else []


def scope_type_kinds(parameters: dict[str, Any]) -> dict[str, str | None]:
    """Map each search scope `type` value to its scope `kind`.

    A type offered under two kinds maps to None (ambiguous: the caller must name the kind).
    Returns an empty mapping when the schema declares no enumerated scope types.
    """
    scope = (parameters.get("properties") or {}).get("scope")
    mapping: dict[str, str | None] = {}
    for option in alternatives(scope, parameters):
        properties = option.get("properties") or {}
        kinds = _values(properties.get("kind"), parameters)
        if len(kinds) != 1 or not isinstance(kinds[0], str):
            continue
        for value in _values(properties.get("type"), parameters):
            if not isinstance(value, str):
                continue
            mapping[value] = kinds[0] if mapping.get(value, kinds[0]) == kinds[0] else None
    return mapping


def argument_defaults(parameters: dict[str, Any]) -> dict[str, Any]:
    """Return the declared default of each top-level argument that has one."""
    defaults: dict[str, Any] = {}
    for name, schema in (parameters.get("properties") or {}).items():
        schema = resolve(schema, parameters)
        if isinstance(schema, dict) and "default" in schema:
            defaults[name] = schema["default"]
    return defaults


def compact_catalog(tools: list[tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
    """Summarise tool schemas for the agent: argument shapes inline, named enums listed once.

    Args:
        tools: (name, description, parameters) of each advertised tool.

    Returns:
        {"tools": [{"name", "description", "arguments"}], "enums": {name: values or
        {"values", "description"}}}. Validation still uses the full schemas.
    """
    enums: dict[str, Any] = {}
    summary = []
    for name, description, parameters in tools:
        required = set(parameters.get("required") or [])
        arguments = {
            arg: _describe(schema, parameters, enums, 0)
            + ("" if arg in required else " (optional)")
            for arg, schema in (parameters.get("properties") or {}).items()
        }
        summary.append({"name": name, "description": description, "arguments": arguments})
    return {"tools": summary, "enums": enums}


def _describe(schema: Any, root: dict[str, Any], enums: dict[str, Any], depth: int) -> str:
    if depth > _MAX_DEPTH:
        return "object"
    if isinstance(schema, dict) and isinstance(schema.get("$ref"), str):
        target = resolve(schema, root)
        name = schema["$ref"].rsplit("/", 1)[-1]
        if isinstance(target, dict) and isinstance(target.get("enum"), list):
            if name not in enums:
                description = target.get("description")
                enums[name] = (
                    {"values": target["enum"], "description": description}
                    if isinstance(description, str) and description
                    else target["enum"]
                )
            return name
        return _describe(target, root, enums, depth + 1)
    if not isinstance(schema, dict):
        return "any"

    options = [
        option
        for key in ("anyOf", "oneOf")
        for option in (schema.get(key) or [])
        if not (isinstance(option, dict) and option.get("type") == "null")
    ]
    if options:
        text = " | ".join(_describe(option, root, enums, depth + 1) for option in options)
    elif "const" in schema:
        text = repr(schema["const"])
    elif isinstance(schema.get("enum"), list):
        text = " | ".join(repr(value) for value in schema["enum"])
    elif schema.get("type") == "array":
        text = f"list of {_describe(schema.get('items', {}), root, enums, depth + 1)}"
        if schema.get("minItems"):
            text += f" (at least {schema['minItems']})"
    elif schema.get("type") == "object" or "properties" in schema:
        required = set(schema.get("required") or [])
        fields = [
            f"{key}{'' if key in required else '?'}: {_describe(value, root, enums, depth + 1)}"
            for key, value in (schema.get("properties") or {}).items()
        ]
        text = "{" + ", ".join(fields) + "}"
    else:
        text = str(schema.get("type") or "any")
        labels = (("minLength", "min length"), ("minimum", "min"), ("default", "default"))
        limits = [
            f"{label} {schema[key]}"
            for key, label in labels
            if key in schema and schema[key] is not None
        ]
        if limits:
            text += f" ({', '.join(limits)})"

    description = schema.get("description")
    if (
        depth == 0
        and isinstance(description, str)
        and description
        and (schema.get("type") in _SCALAR_TYPES or "properties" in schema or options)
    ):
        text += f" — {description[:_MAX_ARG_DESCRIPTION]}"
    return text
