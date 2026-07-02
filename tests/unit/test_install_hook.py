import pytest
from pathlib import Path
from unittest.mock import patch
import shutil

from hooks.install_hook import (
    install_hook,
    uninstall_hook,
    MARKER_BEGIN,
    MARKER_END,
)

def test_install_and_uninstall_hook(tmp_path, monkeypatch):
    """Test that install_hook writes a marked block and uninstall_hook removes it cleanly."""
    # Create a fake shell RC file
    fake_rc = tmp_path / ".fake_rc"
    fake_rc.write_text("# Initial content\n", encoding="utf-8")
    
    # Mock _detect_shell_rc to return our fake rc file
    monkeypatch.setattr("hooks.install_hook._detect_shell_rc", lambda: ("fake_shell", str(fake_rc)))
    
    # Mock home directory for target script copying
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)
    
    # Test installation aborted when yes is False (simulating non-interactive/default abort or EOF)
    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    success_abort = install_hook(yes=False)
    assert not success_abort
    assert MARKER_BEGIN not in fake_rc.read_text(encoding="utf-8")
    
    # Test installation with yes=True
    success = install_hook(yes=True)
    assert success
    
    # Verify installation added the block to RC file
    rc_content = fake_rc.read_text(encoding="utf-8")
    assert MARKER_BEGIN in rc_content
    assert MARKER_END in rc_content
    assert 'source "$HOME/.local/share/tracetree/hooks/shell_hook.sh"' in rc_content
    
    # Verify the hook script was copied to fake home
    target_hook = fake_home / ".local" / "share" / "tracetree" / "hooks" / "shell_hook.sh"
    assert target_hook.exists()
    
    # Test uninstallation aborted when yes is False
    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    un_success_abort = uninstall_hook(yes=False)
    assert not un_success_abort
    assert MARKER_BEGIN in fake_rc.read_text(encoding="utf-8")
    
    # Test uninstallation with yes=True
    un_success = uninstall_hook(yes=True)
    assert un_success
    
    # Verify RC file content is clean again
    rc_content_after = fake_rc.read_text(encoding="utf-8")
    assert MARKER_BEGIN not in rc_content_after
    assert MARKER_END not in rc_content_after
    assert "# Initial content" in rc_content_after.strip()
    
    # Verify hook script was removed
    assert not target_hook.exists()
