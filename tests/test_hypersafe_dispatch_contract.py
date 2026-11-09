#!/usr/bin/env python3
"""Keep filesystem-specific Hypersafe metadata behind dispatch functions."""

from pathlib import Path
import re


SOURCE = Path("src/app.c")
TEXT = SOURCE.read_text(encoding="utf-8")


def function_body(name: str) -> str:
    definition = re.search(
        rf"static\s+[A-Za-z_][A-Za-z0-9_\s*]*\s+{re.escape(name)}\s*\(",
        TEXT,
    )
    assert definition is not None, f"missing function: {name}"
    start = definition.start()
    opening = TEXT.find("{", start)
    assert opening >= 0, f"missing function body: {name}"
    depth = 0
    for position in range(opening, len(TEXT)):
        character = TEXT[position]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return TEXT[opening:position + 1]
    raise AssertionError(f"unterminated function body: {name}")


selected_dispatch = function_body("run_hypersafe_selected_recovery_mode")
assert "run_ntfs_hypersafe_selected_recovery_mode(config)" in selected_dispatch
assert "run_hfsplus_hypersafe_selected_recovery_mode(config)" in selected_dispatch
for ntfs_detail in (
    "NtfsHypersafeResult",
    "MftprobePartialNtfsSource",
    "MftEngineUsersOptions",
    "mft_engine_",
    "$MFT",
):
    assert ntfs_detail not in selected_dispatch, (
        f"generic selected-folder dispatcher contains NTFS detail: {ntfs_detail}"
    )

ntfs_selected = function_body("run_ntfs_hypersafe_selected_recovery_mode")
assert "NtfsHypersafeResult" in ntfs_selected
assert "MftprobePartialNtfsSource" in ntfs_selected
assert "mft_engine_write_selected_tree_ddrescue_domain_partial_with_options" in ntfs_selected
assert "mft_engine_run_selected_partial_recovery" in ntfs_selected
assert "state.image_only = config->image_only ? 1 : 0;" in ntfs_selected
assert "if (!config->image_only)" in ntfs_selected
assert "state.selected_files > 0U && !config->image_only" in ntfs_selected
assert '"final_image_summary"' in ntfs_selected
assert '"Hypersafe image-only completed;' in ntfs_selected

folder_dispatch = function_body("run_hypersafe_folder_fetch_mode")
assert "run_ntfs_hypersafe_folder_fetch_mode(" in folder_dispatch
assert "run_hfsplus_hypersafe_folder_fetch_mode(" in folder_dispatch
assert "NtfsHypersafeResult" not in folder_dispatch
assert "$MFT" not in folder_dispatch

identity_dispatch = function_body("hypersafe_check_existing_artifacts_identity")
assert "ntfs_hypersafe_check_existing_artifacts_identity(" in identity_dispatch
assert "NtfsHypersafeResult" not in identity_dispatch

pre_input_dispatch = function_body("app_dispatch_pre_input_modes")
assert "run_hypersafe_selected_recovery_mode(config)" in pre_input_dispatch
assert "run_ntfs_hypersafe_selected_recovery_mode(config)" not in pre_input_dispatch
assert "hypersafe_recovery_was_interrupted(config)" in pre_input_dispatch
assert "mft_engine_" not in pre_input_dispatch

interrupted_dispatch = function_body("hypersafe_recovery_was_interrupted")
assert "ntfs_hypersafe_recovery_was_interrupted()" in interrupted_dispatch
assert "mft_engine_" not in interrupted_dispatch

preview_dispatch = function_body("run_root_folder_preview_mode")
assert "run_ntfs_root_folder_preview_mode(config)" in preview_dispatch
for ntfs_detail in (
    "NtfsHypersafeResult",
    "MftprobePartialNtfsSource",
    "ntfs_hypersafe_",
    "mft_engine_",
    "$MFT",
):
    assert ntfs_detail not in preview_dispatch, (
        f"generic folder-preview dispatcher contains NTFS detail: {ntfs_detail}"
    )

ntfs_preview = function_body("run_ntfs_root_folder_preview_mode")
assert "NtfsHypersafeResult" in ntfs_preview
assert "MftprobePartialNtfsSource" in ntfs_preview
assert "ntfs_hypersafe_load_status(" in ntfs_preview
assert "mft_engine_list_root_folders_partial(" in ntfs_preview

print("Hypersafe filesystem dispatch contract checks passed")
