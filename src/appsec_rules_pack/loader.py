"""File loading helpers for AppSec rules pack validation.

Rule packs are untrusted input: they arrive in pull requests and are validated by CI.
The loader therefore narrows YAML to what a rules pack needs. It refuses aliases,
because alias expansion turns a few hundred bytes into millions of nodes (CWE-776) and
lets a pack refer to itself. It refuses duplicate mapping keys, because PyYAML keeps
the last value silently, so a reviewer could read one value while another one wins.
It also refuses files larger than ``MAX_RULES_FILE_BYTES`` before parsing them, and
reports an unquoted date that is not a real day as a YAML error instead of letting
PyYAML's ValueError escape.
"""

from pathlib import Path
from typing import Any

import yaml
from yaml.composer import ComposerError
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

MAX_RULES_FILE_BYTES = 10 * 1024 * 1024


class RulesFileTooLargeError(yaml.MarkedYAMLError):
    """Raised when a rules file exceeds ``MAX_RULES_FILE_BYTES``."""


class _RulesPackLoader(yaml.SafeLoader):
    """SafeLoader that rejects aliases and duplicate mapping keys."""

    def compose_node(self, parent: Node | None, index: Any) -> Node | None:
        if self.check_event(AliasEvent):
            event = self.peek_event()
            raise ComposerError(
                None,
                None,
                "YAML aliases are not supported in rules packs",
                event.start_mark,
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
            except TypeError:
                # An unhashable key fails in the base constructor with its own message.
                continue
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"duplicate key {_key_label(key)}",
                    key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)

    def construct_yaml_timestamp(self, node: ScalarNode) -> Any:
        try:
            return super().construct_yaml_timestamp(node)
        except ValueError as error:
            raise ConstructorError(
                None,
                None,
                f"{_key_label(node.value)} is not a valid date or timestamp ({error})",
                node.start_mark,
            ) from error


# SafeLoader looks constructors up in a per-class registry, so the override above has to
# be registered for the timestamp tag to take effect.
_RulesPackLoader.add_constructor(
    "tag:yaml.org,2002:timestamp", _RulesPackLoader.construct_yaml_timestamp
)


def _key_label(key: Any) -> str:
    text = str(key)
    return repr(text if len(text) <= 60 else text[:57] + "...")


Position = tuple[int, int]


def yaml_positions(path: Path) -> dict[tuple[Any, ...], Position]:
    """Map the path of every node in a rules file to its 1-based line and column.

    Paths use the same keys and list indexes as validation issues, so an issue can be
    located in the file it came from. Call it only on a file that already loaded.
    """

    with path.open("r", encoding="utf-8") as handle:
        loader = _RulesPackLoader(handle)
        try:
            root = loader.get_single_node()
        finally:
            loader.dispose()

    positions: dict[tuple[Any, ...], Position] = {}
    stack: list[tuple[tuple[Any, ...], Node | None]] = [((), root)]
    while stack:
        node_path, node = stack.pop()
        if node is None:
            continue
        positions[node_path] = (node.start_mark.line + 1, node.start_mark.column + 1)
        if isinstance(node, MappingNode):
            stack.extend(
                ((*node_path, key.value), value)
                for key, value in node.value
                if isinstance(key, ScalarNode)
            )
        elif isinstance(node, SequenceNode):
            stack.extend(((*node_path, index), item) for index, item in enumerate(node.value))
    return positions


def load_yaml_file(path: Path) -> Any:
    """Load a rules pack YAML file with safe, restricted parsing."""

    size = path.stat().st_size
    if size > MAX_RULES_FILE_BYTES:
        raise RulesFileTooLargeError(
            problem=(
                f"file is {size} bytes; the maximum supported rules file size is "
                f"{MAX_RULES_FILE_BYTES} bytes"
            )
        )

    with path.open("r", encoding="utf-8") as handle:
        # Same sequence yaml.safe_load uses, with the restricted SafeLoader subclass.
        loader = _RulesPackLoader(handle)
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()
