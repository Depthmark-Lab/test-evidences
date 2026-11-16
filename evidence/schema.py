"""Small JSON Schema validator. Standard library only.

Supports a deliberate subset of JSON Schema:
  type, properties, required, additionalProperties, items,
  enum, const, pattern, minLength, minItems
Any other keyword is rejected when the schema is checked, so a rule is never
silently ignored. Swap in a full validator if you need more keywords.
"""
from __future__ import annotations

import re

ANNOTATIONS = {"$schema", "$id", "title", "description"}
KEYWORDS = {
    "type", "properties", "required", "additionalProperties", "items",
    "enum", "const", "pattern", "minLength", "minItems",
}
TYPE_NAMES = {"object", "array", "string", "integer", "number", "boolean", "null"}


class SchemaError(Exception):
    """The schema itself is not usable."""


def check_schema(schema, path="$"):
    """Raise SchemaError if the schema uses anything this validator cannot enforce."""
    if not isinstance(schema, dict):
        raise SchemaError(f"{path}: a schema must be an object")
    unknown = set(schema) - KEYWORDS - ANNOTATIONS
    if unknown:
        raise SchemaError(f"{path}: unsupported keyword(s): {', '.join(sorted(unknown))}")
    for name in _type_names(schema):
        if name not in TYPE_NAMES:
            raise SchemaError(f"{path}: unknown type '{name}'")
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except re.error as exc:
            raise SchemaError(f"{path}: bad pattern: {exc}") from None
    for name, sub in schema.get("properties", {}).items():
        check_schema(sub, f"{path}.{name}")
    if isinstance(schema.get("additionalProperties"), dict):
        check_schema(schema["additionalProperties"], f"{path}.*")
    if "items" in schema:
        check_schema(schema["items"], f"{path}[]")


def validate(value, schema, path="$"):
    """Return a list of problems. An empty list means the value matches the schema."""
    names = _type_names(schema)
    if names and not any(_is_type(value, name) for name in names):
        return [f"{path}: expected {' or '.join(names)}, got {_describe(value)}"]

    errors = []
    if "enum" in schema and not any(_same(value, option) for option in schema["enum"]):
        errors.append(f"{path}: must be one of {schema['enum']}")
    if "const" in schema and not _same(value, schema["const"]):
        errors.append(f"{path}: must be {schema['const']!r}")

    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: does not match pattern {schema['pattern']}")
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than {schema['minLength']} characters")

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "items" in schema:
            for index, item in enumerate(value):
                errors += validate(item, schema["items"], f"{path}[{index}]")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{path}: missing required field '{name}'")
        extra = schema.get("additionalProperties", True)
        for name, item in value.items():
            if name in properties:
                errors += validate(item, properties[name], f"{path}.{name}")
            elif extra is False:
                errors.append(f"{path}: unexpected field '{name}'")
            elif isinstance(extra, dict):
                errors += validate(item, extra, f"{path}.{name}")
    return errors


def _type_names(schema):
    names = schema.get("type")
    if names is None:
        return []
    return [names] if isinstance(names, str) else list(names)


def _is_type(value, name):
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, {"object": dict, "array": list, "string": str, "null": type(None)}[name])


def _same(left, right):
    # In Python True == 1. JSON treats them as different values.
    return type(left) is type(right) and left == right


def _describe(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    return {dict: "object", list: "array", str: "string", int: "integer", float: "number"}.get(type(value), type(value).__name__)
