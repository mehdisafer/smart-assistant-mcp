"""Security regressions for the generic, sanitized public MCP core."""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from smart_assistant_mcp.common import RuntimeFault
from smart_assistant_mcp.desktop_compat import DesktopCompatibility, WRITE_TOOLS
from smart_assistant_mcp.filesystem import FileSystem, PathPolicy
from smart_assistant_mcp.searches import SearchManager


class GovernorStub:
    def __init__(self):
        self.leases = set()

    def acquire(self, key, *args):
        self.leases.add(key)

    def release(self, key):
        self.leases.discard(key)


@pytest.fixture
def stack(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    governor = GovernorStub()
    policy = PathPolicy({"p": root})
    manager = SearchManager(policy, tmp_path / "search_state", governor)
    return root, policy, manager, governor


def search(manager, *, pattern="SEARCH_CANARY", include_hidden=True,
           search_type="content", literal=True):
    admitted = manager.start("owner", "p", "", pattern, search_type=search_type,
                             include_hidden=include_hidden, literal=literal,
                             context_lines=0, timeout_seconds=10)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        response = manager.results("owner", admitted["id"])
        if response["session"]["status"] not in {"QUEUED", "RUNNING"}:
            assert response["session"]["status"] == "COMPLETED", response
            return {row["path"].replace("\\", "/") for row in response["results"]}
        time.sleep(.025)
    pytest.fail("Search worker did not finish its bounded fixture")


def test_regular_and_nonsecret_hidden_search(stack):
    root, policy, manager, governor = stack
    (root / "allowed.txt").write_text("SEARCH_CANARY", encoding="utf-8")
    (root / ".notes.txt").write_text("SEARCH_CANARY", encoding="utf-8")
    assert search(manager) == {"allowed.txt", ".notes.txt"}
    assert search(manager, include_hidden=False) == {"allowed.txt"}
    assert not governor.leases


@pytest.mark.parametrize("name", [".env", ".env.local", "credentials/key.txt",
                                   ".ssh/id_rsa", "nested/Secrets/token.txt",
                                   ".azure/config.json"])
def test_hidden_and_protected_paths_never_leak(stack, name):
    root, _, manager, _ = stack
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("SEARCH_CANARY", encoding="utf-8")
    (root / "ok.txt").write_text("SEARCH_CANARY", encoding="utf-8")
    assert search(manager, include_hidden=True) == {"ok.txt"}
    assert search(manager, include_hidden=False) == {"ok.txt"}
    assert name.replace("\\", "/") not in search(
        manager, pattern="*", include_hidden=True, search_type="files", literal=False)


def test_external_file_symlink_refused(stack, tmp_path):
    root, policy, manager, _ = stack
    outside = tmp_path / "outside.txt"
    outside.write_text("SEARCH_CANARY", encoding="utf-8")
    link = root / "alias.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlink unavailable on this host: {exc}")
    assert not search(manager)
    with pytest.raises(RuntimeFault):
        with policy.open_project_file("p", "alias.txt"):
            pass


def test_external_directory_symlink_refused(stack, tmp_path):
    root, _, manager, _ = stack
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.txt").write_text("SEARCH_CANARY", encoding="utf-8")
    try:
        (root / "dirlink").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Directory symlink unavailable: {exc}")
    assert not search(manager)


@pytest.mark.skipif(os.name != "nt", reason="NTFS junction requires Windows")
def test_external_junction_refused(stack, tmp_path):
    root, _, manager, _ = stack
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.txt").write_text("SEARCH_CANARY", encoding="utf-8")
    link = root / "junction"
    outcome = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(link), str(outside)],
                             capture_output=True, text=True)
    if outcome.returncode:
        pytest.skip("Junction creation unavailable")
    assert not search(manager)


def test_opened_file_is_regular_and_scoped(stack):
    root, policy, _, _ = stack
    (root / "ok.txt").write_bytes(b"safe")
    with policy.open_project_file("p", "ok.txt") as source:
        assert source.read() == b"safe"
    (root / ".env").write_bytes(b"secret")
    for name in (".env", "../outside.txt"):
        with pytest.raises(RuntimeFault):
            with policy.open_project_file("p", name):
                pass


@pytest.fixture
def desktop(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    policy = PathPolicy({"p": root}, {"p": ["parent/immutable"]})
    files = FileSystem(policy, tmp_path / "files_state")
    manager = SimpleNamespace(specs={"desktop": {"call_timeout_seconds": 5}})
    return root, policy, files, manager


@pytest.mark.parametrize("tool", sorted(WRITE_TOOLS))
def test_global_mutation_switch_denies_every_desktop_writer(desktop, tmp_path, tool):
    root, policy, files, manager = desktop
    adapter = DesktopCompatibility(policy, files, manager,
                                   tmp_path / "compat", allow_mutations=False)
    with pytest.raises(RuntimeFault) as exc:
        adapter.normalize(tool, {}, "p")
    assert exc.value.code == "MUTATIONS_DISABLED"
    (root / "ok.txt").write_text("ok", encoding="utf-8")
    args, paths, *_ = adapter.normalize("read_file", {"path": "ok.txt"}, "p")
    assert paths == [root / "ok.txt"]


def test_desktop_explicit_allow_is_only_admission(desktop, tmp_path):
    root, policy, files, manager = desktop
    adapter = DesktopCompatibility(policy, files, manager,
                                   tmp_path / "compat", allow_mutations=True)
    _, paths, key, _ = adapter.normalize(
        "create_directory", {"path": "new", "_request_key": "test-key-012345"}, "p")
    assert key == "test-key-012345"
    assert paths == [root / "new"]
    assert not paths[0].exists()


def test_move_rejects_immutable_descendant(desktop, tmp_path):
    root, policy, files, manager = desktop
    (root / "parent" / "immutable").mkdir(parents=True)
    adapter = DesktopCompatibility(policy, files, manager,
                                   tmp_path / "compat", allow_mutations=True)
    with pytest.raises(RuntimeFault) as exc:
        adapter.normalize("move_file", {
            "source": "parent", "destination": "new_parent",
            "_request_key": "move-key-123456", "_expected_sha256": "0" * 64}, "p")
    assert exc.value.code == "IMMUTABLE_PATH"
    assert (root / "parent" / "immutable").is_dir()


def test_move_regular_tree_is_admissible_not_executed(desktop, tmp_path):
    root, policy, files, manager = desktop
    (root / "movable").mkdir()
    adapter = DesktopCompatibility(policy, files, manager,
                                   tmp_path / "compat", allow_mutations=True)
    _, paths, *_ = adapter.normalize("move_file", {
        "source": "movable", "destination": "new_movable",
        "_request_key": "move-key-123456", "_expected_sha256": "0" * 64}, "p")
    assert paths == [root / "movable", root / "new_movable"]
    assert paths[0].exists() and not paths[1].exists()


def test_move_rejects_secret_descendant(desktop):
    root, policy, _, _ = desktop
    (root / "ordinary").mkdir()
    (root / "ordinary" / ".env.local").write_text("secret", encoding="utf-8")
    with pytest.raises(RuntimeFault) as exc:
        policy.require_movable_tree(root / "ordinary")
    assert exc.value.code == "PROTECTED_MUTATION_PATH"


def test_move_rejects_immutable_even_before_creation(desktop):
    root, policy, _, _ = desktop
    (root / "parent").mkdir()
    with pytest.raises(RuntimeFault) as exc:
        policy.require_movable_tree(root / "parent")
    assert exc.value.code == "IMMUTABLE_PATH"


def test_open_handle_cannot_be_redirected_to_different_inode(stack, tmp_path, monkeypatch):
    """Simulate an adversarial replacement between path admission and OS open."""
    from smart_assistant_mcp import filesystem as fs_module

    root, policy, _, _ = stack
    allowed = root / "allowed.txt"
    allowed.write_text("public", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("do not read", encoding="utf-8")
    original_open = fs_module.os.open

    def redirect(path, flags, *args, **kwargs):
        if Path(path) == allowed:
            return original_open(outside, flags, *args, **kwargs)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(fs_module.os, "open", redirect)
    with pytest.raises(RuntimeFault) as exc:
        with policy.open_project_file("p", "allowed.txt"):
            pytest.fail("An unverified OS handle reached the caller")
    assert exc.value.code == "PATH_CHANGED"


def test_move_rejects_unregistered_symlink_descendant(desktop, tmp_path):
    root, policy, _, _ = desktop
    source = root / "movable"
    source.mkdir()
    external = tmp_path / "outside"
    external.mkdir()
    try:
        (source / "untrusted").symlink_to(external, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Directory symlink unavailable: {exc}")
    with pytest.raises(RuntimeFault) as raised:
        policy.require_movable_tree(source)
    assert raised.value.code == "REPARSE_POINT"


def test_move_tree_scan_limit_is_fail_closed(desktop):
    root, policy, _, _ = desktop
    source = root / "movable"
    source.mkdir()
    for index in range(3):
        (source / f"file-{index}.txt").write_text("safe", encoding="utf-8")
    with pytest.raises(RuntimeFault) as raised:
        policy.require_movable_tree(source, limit=2)
    assert raised.value.code == "PROTECTED_TREE_SCAN_BOUND"


def test_desktop_tool_catalog_excludes_writes_when_disabled(desktop, tmp_path):
    import asyncio
    from contextlib import asynccontextmanager

    root, policy, files, _ = desktop

    class FakeTool:
        def __init__(self, name):
            self.name = name

        def model_dump(self, mode="json", by_alias=True):
            return {"name": self.name, "inputSchema": {
                "type": "object", "properties": {"path": {"type": "string"}},
                "required": ["path"]}}

    class FakeManager:
        specs = {"desktop": {"call_timeout_seconds": 5}}

        @asynccontextmanager
        async def use(self, backend, project, partition=None):
            assert backend == "desktop" and project == "p"
            yield SimpleNamespace(catalog={
                "read_file": FakeTool("read_file"),
                "create_directory": FakeTool("create_directory")})

    manager = FakeManager()
    readonly = DesktopCompatibility(policy, files, manager,
                                    tmp_path / "read_only_adapter", allow_mutations=False)
    writable = DesktopCompatibility(policy, files, manager,
                                    tmp_path / "writable_adapter", allow_mutations=True)
    visible_readonly = asyncio.run(readonly.tools("p", "owner"))["tools"]
    visible_writable = asyncio.run(writable.tools("p", "owner"))["tools"]
    assert [tool["name"] for tool in visible_readonly] == ["read_file"]
    assert {tool["name"] for tool in visible_writable} == {"read_file", "create_directory"}


def test_native_direct_read_revalidates_opened_file(stack, tmp_path, monkeypatch):
    import smart_assistant_mcp.filesystem as module

    root, policy, _, _ = stack
    target = root / "normal.txt"
    target.write_text("original", encoding="utf-8")
    alternate = tmp_path / "other.txt"
    alternate.write_text("alternate", encoding="utf-8")
    reader = FileSystem(policy, tmp_path / "state")
    assert reader.read("p", "normal.txt")["content"] == "original"
    saved = module.os.open

    def redirected(path, flags, *args, **kwargs):
        if Path(path) == target:
            return saved(alternate, flags, *args, **kwargs)
        return saved(path, flags, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", redirected)
    with pytest.raises(RuntimeFault) as err:
        reader.read("p", "normal.txt")
    assert err.value.code == "PATH_CHANGED"


def test_direct_read_blocks_protected_name(stack, tmp_path):
    root, policy, _, _ = stack
    (root / ".env").write_text("fixture", encoding="utf-8")
    reader = FileSystem(policy, tmp_path / "state")
    with pytest.raises(RuntimeFault):
        reader.read("p", ".env")
