#!/usr/bin/env python3
"""Small source guard for the autonomous raw-all post-scan contract."""

from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "src" / "app.c"
TEXT = SOURCE.read_text(encoding="utf-8")
HFS_SOURCE = SOURCE.with_name("hfsplus_backend.c")
HFS_TEXT = HFS_SOURCE.read_text(encoding="utf-8")


def function_body(name: str) -> str:
    markers = (
        f"static int {name}(",
        f"static void {name}(",
        f"static unsigned long long {name}(",
    )
    starts = [TEXT.rfind(marker) for marker in markers]
    start = max(starts)
    if start < 0:
        raise AssertionError(f"function not found: {name}")
    brace = TEXT.index("{", start)
    depth = 0
    for index in range(brace, len(TEXT)):
        if TEXT[index] == "{":
            depth += 1
        elif TEXT[index] == "}":
            depth -= 1
            if depth == 0:
                return TEXT[start:index + 1]
    raise AssertionError(f"unterminated function: {name}")


gap_retry = function_body("run_coverage_gap_reread")
post_scan = function_body("run_post_scan_retry_and_metadata_reacquire")
supervisor = function_body("maybe_run_under_crash_supervisor")
hfs_terminal_finalize = function_body("run_hfsplus_final_reconcile_until_ready")
resume_coverage_refresh = function_body("refresh_saved_coverage_verdict_after_resume")
startup_metadata_phase = function_body("raw_all_startup_stage_is_metadata_phase")
startup_timeout = function_body("raw_all_startup_stage_timeout_seconds")
gui_terminal_pass = function_body("app_gui_end_pass_if_running")
report_content_index = function_body("update_recovered_content_index_for_report")
run_log_report = function_body("write_run_log_report")
repair_hfs_lookup_status = function_body(
    "repair_saved_hfsplus_lookup_ready_status"
)
validator_escape = function_body(
    "maybe_advance_scan_state_past_stalled_validator"
)
restore_backend_identity = function_body(
    "raw_all_stage_restore_saved_backend_identity"
)
write_raw_stage = function_body("write_raw_all_stage_file_with_metrics")
stall_guard = function_body("raw_all_child_should_restart_for_stall")
stall_rewind = function_body("maybe_rewind_scan_state_for_stall_retry")
scan_completed_from_stage = function_body(
    "raw_all_stage_indicates_scan_completed"
)
repair_false_end_cursor = function_body(
    "raw_all_repair_false_end_cursor_from_trailing_gap"
)
prepare_scan_state = function_body("app_prepare_scan_state_context")

assert "retry_budget_bytes = total_gap_bytes;" in gap_retry
assert "attempted_bytes >= retry_budget_bytes" in gap_retry
assert "yielding after zero useful delta" not in gap_retry
assert "leaving remaining gaps for a later explicit retry" not in gap_retry

# Coverage gathered by the last retry chunk must reach disk before the final
# gap verdict is recalculated.  Otherwise a successfully closed gap remains
# stale in coverage_gaps.tsv and in the HFS+ measurement summary.
coverage_flush_at = gap_retry.index("app_gui_flush_current_coverage();")
coverage_rediscovery_at = gap_retry.index(
    "discover_coverage_gaps_for_run_dir(", coverage_flush_at
)
assert coverage_flush_at < coverage_rediscovery_at

skip_notice = "Skipping the repeatedly stalled hotspot reread"
skip_at = post_scan.index(skip_notice)
coverage_at = post_scan.index("run_coverage_gap_reread")
assert skip_at < coverage_at
assert "return 1;" not in post_scan[skip_at:coverage_at]

assert "!allow_forward_bypass" in TEXT
assert "completed_with_unreadable_ranges" in TEXT
assert "g_raw_all_coverage_retry_exhausted) ? 1 : 0" in TEXT
assert "before_post_scan_reconcile" not in TEXT
assert "Finalize write-pressure pause:" not in TEXT

# HFS+ reconcile is resumable work, not a one-shot best effort.  Every route
# that can finish/reopen a raw run must verify the durable ready marker, while
# a completed byte scope must not take the early exit over a partial marker.
assert "state.finalize_state_ready" in hfs_terminal_finalize
assert "no_progress_slices >= 3U" in hfs_terminal_finalize
assert TEXT.count("run_hfsplus_final_reconcile_until_ready(") >= 5
assert "!saved_hfsplus_finalize_is_pending(config.output_dir)" in TEXT
assert "their naming is deferred to the dedicated bounded final reconcile stage" in gap_retry
assert "gap_count > 0U" in resume_coverage_refresh
assert "complete_with_terminal_ranges" in resume_coverage_refresh
assert TEXT.count("refresh_saved_coverage_verdict_after_resume(") >= 4
assert "fs_backend_finish_sequential_measurement(\n            raw_all_full_completion_confirmed" in TEXT
final_verdict_at = TEXT.rindex('"final_completion_check"')
final_measurement_at = TEXT.index(
    "fs_backend_finish_sequential_measurement(", final_verdict_at
)
terminal_reconcile_at = TEXT.index(
    '"after revisit and coverage reread"', final_measurement_at
)
assert final_verdict_at < final_measurement_at < terminal_reconcile_at

# One damaged coverage chunk has one durable wall-clock allowance shared by
# all supervised child restarts.  Exhaustion must become a saved red terminal
# range and an automatic forward restart, never an unbounded fifth child.
assert "#define RAW_ALL_COVERAGE_ZONE_MAX_SECONDS 600ULL" in TEXT
assert "zone_started_unix=" in TEXT
assert "supervisor_pid=" in TEXT
assert "coverage_zone_elapsed_seconds >=" in supervisor
assert "append_terminal_coverage_range_for_run_dir" in supervisor
assert "coverage_terminal_ranges.tsv" in TEXT
assert 'app_gui_note_trouble(start_offset, end_offset, "coverage_unreadable")' in TEXT

# A stalled validator is identified while its child is still alive.  The
# exact stage snapshot must survive termination; re-reading raw_all_stage
# after kill races with shutdown telemetry (for example "writer catching
# up") and used to make the safe escape fail.  A repeated trouble-map zone
# must move the cursor beyond the whole known zone, not one MiB farther into
# it, while the skipped span remains durably deferred before scan_state moves.
assert "RawAllStageState validator_escape_stage = {0};" in supervisor
assert "&validator_escape_stage" in supervisor
assert "const RawAllStageState *captured_stage" in validator_escape
assert "stage = *captured_stage;" in validator_escape
assert "raw_all_stalled_stage_is_candidate_validation(" not in validator_escape
assert "load_best_trouble_map_entry_for_offset(" in validator_escape
assert "trouble_resume = trouble_entry.end_offset;" in validator_escape
assert "trouble_entry.hit_count >= 2ULL" in validator_escape
defer_at = validator_escape.index("remember_deferred_bad_zone(")
scan_state_at = validator_escape.index("scan_state_write(")
assert defer_at < scan_state_at

# The supervisor process owns no configured filesystem backend and starts
# with the facade's legacy NTFS default.  It must preserve identity written by
# the configured child, so a terminal HFS+ run cannot turn into NTFS merely
# because the parent publishes the final status line.
assert "getenv(CRASH_RETRY_CHILD_ENV) != NULL" in write_raw_stage
assert "raw_all_stage_state_has_backend_identity(&next_state)" in write_raw_stage
known_identity_at = restore_backend_identity.index(
    "raw_all_stage_state_has_backend_identity(state)"
)
saved_ntfs_at = restore_backend_identity.index(
    "load_saved_ntfs_backend_identity_for_run"
)
saved_hfs_at = restore_backend_identity.index(
    "load_saved_hfsplus_artifact_state_for_run"
)
assert known_identity_at < saved_ntfs_at < saved_hfs_at

# The ordinary retry path needs the same pre-kill protection as validator
# escape.  A reader_open child once published post_scan_reconcile while being
# terminated; re-reading that label after kill moved a 26 GiB cursor to the
# end of a 320 GB disk.  Capture the current child state in the stall guard,
# pass it through the supervisor, and forbid the rewind helper from loading a
# newer raw_all_stage file after termination.
assert "RawAllStageState *out_stage_state" in stall_guard
assert "*out_stage_state = stage_state;" in stall_guard
assert "RawAllStageState stalled_child_stage = {0};" in supervisor
assert "&stalled_child_stage" in supervisor
assert "const RawAllStageState *captured_stage" in stall_rewind
assert "stage_state = *captured_stage;" in stall_rewind
assert "load_raw_all_stage_state(" not in stall_rewind

# Phase names are status text, not durable coverage evidence.  Completion
# needs either scan-loop bytes reaching their bound or explicit scope flags.
assert 'strcmp(state->stage, "scan_loop") == 0' in scan_completed_from_stage
assert "state->selected_scope_complete || state->full_source_complete" in (
    scan_completed_from_stage
)
assert '"post_scan_reconcile"' not in scan_completed_from_stage
assert '"retry_hotspots"' not in scan_completed_from_stage
assert '"done"' not in scan_completed_from_stage

# Runs already damaged by the old race heal themselves on resume when durable
# coverage proves that a very large unread tail remains.  The repair applies
# only to full-source scans, keeps an overlap, clears completion, and is
# skipped when a trusted finalize checkpoint proves the scan really ended.
assert "trusted_completed_scan_checkpoint" in repair_false_end_cursor
assert "discover_coverage_gaps_for_run_dir(" in repair_false_end_cursor
assert "state->source_size / 8ULL" in repair_false_end_cursor
assert "RAW_ALL_COVERAGE_GAP_RETRY_CHUNK_BYTES" in repair_false_end_cursor
assert "repaired_offset -= repaired_offset % RAW_ALL_RESUME_ALIGNMENT" in (
    repair_false_end_cursor
)
assert "state->scan_offset = repaired_offset;" in repair_false_end_cursor
assert "state->scan_completed = 0;" in repair_false_end_cursor
assert "raw_all_repair_false_end_cursor_from_trailing_gap(" in prepare_scan_state
farthest_hint_at = prepare_scan_state.index("recover_raw_all_farthest_resume_hint(")
repair_cursor_at = prepare_scan_state.index(
    "raw_all_repair_false_end_cursor_from_trailing_gap("
)
assert farthest_hint_at < repair_cursor_at

# Revisit telemetry is compact, resume-safe state consumed by Activity; the
# GUI must not derive these counters by walking the recovered output tree.
assert "revisit_status.txt" in TEXT
assert "baseline_recovered=" in TEXT
assert "last_complete_file_unix=" in TEXT

# Reloading durable state is neither a 45-second source-read stall nor a
# reason to move an already complete source cursor backwards.  It keeps a
# finite watchdog so a genuinely wedged loader can still be restarted.
assert "RAW_ALL_RESUME_LOADING_STALL_TIMEOUT_SECONDS 600ULL" in TEXT
assert 'strcmp(stage, "resume_loading") == 0' in startup_metadata_phase
assert "RAW_ALL_RESUME_LOADING_STALL_TIMEOUT_SECONDS" in startup_timeout
assert 'strcmp(stalled_stage, "resume_loading") != 0' in supervisor
assert "restarting artifact loading without rewinding" in supervisor

# Every terminal resume route heals compact revisit telemetry, and the parent
# closes nested GUI passes left running when an earlier child was killed.
assert TEXT.count("raw_all_revisit_status_begin(") >= 5
assert TEXT.count('raw_all_revisit_status_sync("completed")') >= 3
assert 'interrupted ? "stopped" : "completed"' in TEXT
assert 'strcmp(g_gui_pass_rows[i].status, "running") == 0' in gui_terminal_pass
assert '"stopped"' in gui_terminal_pass

# Expensive duplicate evidence is visible as its own bounded final activity,
# rather than leaving a terminal `completed` row on screen while work remains.
assert '"report_index"' in report_content_index
assert '"indexing recovered results"' in report_content_index

# An empty finalized read-error range list does not prove that the source was
# trouble-free.  Silent stalls and remembered problem zones must remain
# visible in the human-readable run log instead of being reported as "none".
assert "RuntimeEventSummary runtime_event_summary = {0};" in run_log_report
assert "trouble_summary.zone_count > 0U" in run_log_report
assert '"- finalized_unreadable_ranges: none\\n"' in run_log_report
assert '"- other_source_read_trouble: observed\\n"' in run_log_report
assert "this does not mean the source was read without trouble" in run_log_report

# A compact mmap index is a fully usable HFS+ metadata lookup even after the
# memory-heavy Catalog model has deliberately been released.
metadata_ready_at = HFS_TEXT.index('fprintf(file, "metadata_lookup_ready=%d\\n"')
metadata_ready_block = HFS_TEXT[metadata_ready_at:metadata_ready_at + 180]
assert "hfsplus_metadata_ready_local() ? 1 : 0" in metadata_ready_block
assert "hfsplus_catalog_available_local() ? 1 : 0" not in metadata_ready_block
assert '"metadata_lookup_ready=1\\n"' in repair_hfs_lookup_status
assert "metadata/index/manifest.bin" in repair_hfs_lookup_status
assert "repair_saved_hfsplus_lookup_ready_status(config.output_dir);" in TEXT

print("raw-all autonomous post-scan contract checks passed")
