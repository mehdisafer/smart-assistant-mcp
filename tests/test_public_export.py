from pathlib import Path

import smart_assistant_mcp


def test_public_version():
    assert smart_assistant_mcp.__version__ == "0.1.0"


def test_private_modules_not_exported():
    package = Path(smart_assistant_mcp.__file__).parent
    assert not (package / "mail.py").exists()
    assert not (package / "notification.py").exists()


def test_no_private_machine_root_in_python_sources():
    package = Path(smart_assistant_mcp.__file__).parent
    text = "\n".join(p.read_text(encoding="utf-8") for p in package.glob("*.py"))
    private_root = "A:" + "\\" + "SMART_ASSISTANT_MCP"
    private_user = "C:" + "\\" + "Users" + "\\" + "mehdi"
    assert private_root not in text
    assert private_user not in text
