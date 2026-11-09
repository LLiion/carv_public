#!/usr/bin/env python3
"""Guard large recovered trees from recursive work in Qt event handlers."""

import ast
import csv
from dataclasses import dataclass
import io
from pathlib import Path
import re
import tempfile
import traceback
import sys


SOURCE = Path("scripts/carv_gui_qt.py")
SOURCE_TEXT = SOURCE.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE_TEXT, filename=str(SOURCE))
GUARDED = {
    "_latest_recovered_output",
    "_populate_done_recovered_tree",
    "_expand_done_recovered_item",
    "_invalidate_done_recovered_item",
}


def call_name(call: ast.Call) -> str:
    function = call.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        owner = function.value.id if isinstance(function.value, ast.Name) else ""
        return f"{owner}.{function.attr}" if owner else function.attr
    return ""


methods = {
    node.name: node
    for node in ast.walk(TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}
missing = GUARDED.difference(methods)
assert not missing, f"missing guarded GUI methods: {sorted(missing)}"
assert "_done_directory_totals" not in methods, "recursive Done totals helper returned"
assert (
    "self.done_recovered_tree.itemCollapsed.connect("
    "self._invalidate_done_recovered_item)"
) in SOURCE_TEXT, "collapsed Done folders do not invalidate their lazy cache"
assert "collapse and reopen a folder to refresh it" in SOURCE_TEXT
assert 'state_dir / "revisit_status.txt"' in SOURCE_TEXT
assert '"POST-SCAN / REVISIT"' in SOURCE_TEXT
assert 'revisit.get("extra_files")' in SOURCE_TEXT
assert 'revisit.get("last_complete_file_unix")' in SOURCE_TEXT
assert "HYPERSAFE_UI_VISIBLE = True" in SOURCE_TEXT
assert 'app.setApplicationName("Carv")' in SOURCE_TEXT
assert 'app.setDesktopFileName("Carv")' in SOURCE_TEXT
assert "QIcon(WRENCH_ICON_PATH)" in SOURCE_TEXT
assert "app.setWindowIcon(app_icon)" in SOURCE_TEXT
assert "window.setWindowIcon(app_icon)" in SOURCE_TEXT
assert SOURCE_TEXT.count(
    "setVisible(\n            HYPERSAFE_UI_VISIBLE\n        )"
) == 1, "the Hypersafe selector must follow the development visibility switch"
assert 'self.hypersafe_enabled_check = QCheckBox("Hypersafe recovery")' in SOURCE_TEXT
assert "def _hypersafe_priority_recovery_requested" in SOURCE_TEXT
assert "hypersafe_priority_recovery = self._hypersafe_priority_recovery_requested()" in SOURCE_TEXT
assert 'else "<folder-search-terms>"' in SOURCE_TEXT
assert 'command_parts.append("--hypersafe-recover")' in SOURCE_TEXT
assert "self.hypersafe_folder_fetch_button.setVisible(False)" in SOURCE_TEXT
assert 'self.image_first_check.setChecked(True)' in SOURCE_TEXT
assert 'self.deep_image_check.setChecked(True)' in SOURCE_TEXT
assert '"3. Tree recovery"' in SOURCE_TEXT
assert 'self.mode_combo.setCurrentText("Tree Recovery")' in SOURCE_TEXT
assert 'self.mode_combo.setCurrentText("Image only")' in SOURCE_TEXT
assert "self.mode_combo.setEnabled(not targeted_mode_active)" in SOURCE_TEXT
assert 'PRESS "PREVIEW FILESYSTEM STRUCTURE" ABOVE' in SOURCE_TEXT
assert '"3. Choose folders from tree"' not in SOURCE_TEXT
assert "def _hypersafe_tree_recovery_requested" in SOURCE_TEXT
assert 'elif hypersafe_targeted_recovery:' in SOURCE_TEXT
assert 'command_parts.append("--hypersafe-recover")' in SOURCE_TEXT
assert 'if image_only and (hypersafe_immediate or hypersafe_targeted_recovery):' in SOURCE_TEXT
assert 'command_parts.append("--image-only")' in SOURCE_TEXT
assert "elif not hypersafe_immediate and not hypersafe_targeted_recovery:" in SOURCE_TEXT
assert "or (hypersafe_tree_selected and hypersafe_preview_active)" not in SOURCE_TEXT
assert "self.image_only_check.setEnabled(not enabled)" not in SOURCE_TEXT
assert 'self.image_only_check = QCheckBox("Image only")' in SOURCE_TEXT
assert 'self.mode_combo.setCurrentText("Image only")' in SOURCE_TEXT
assert "def _mode_text_is_image_only" in SOURCE_TEXT
assert "self._mode_before_image_only" in SOURCE_TEXT
assert "self._syncing_image_only_mode" in SOURCE_TEXT
assert "self.image_only_check.setChecked(False)" in SOURCE_TEXT
assert "and not os.path.isdir(selected_source_path)" in SOURCE_TEXT
assert '"Tree Recovery · Hypersafe"' in SOURCE_TEXT
assert "self.hypersafe_layout_toggle_button" not in SOURCE_TEXT
assert 'command_parts.extend(["--hypersafe", "immediate"])' in SOURCE_TEXT
assert 'QCheckBox("WAIT FOR SOURCE AFTER START")' in SOURCE_TEXT
assert 'WAIT_FOR_NEW_SOURCE_TOKEN = "__CARV_WAIT_FOR_NEW_SOURCE__"' in SOURCE_TEXT
assert '"wait_for_new_source": True' in SOURCE_TEXT
assert '"is_expected_path": True' in SOURCE_TEXT
assert "self.source_panel.set_wait_for_source_enabled(\n                enabled\n            )" in SOURCE_TEXT
assert 'or hypersafe_enabled\n        )' in SOURCE_TEXT
assert 'and not bool((self._selected_source or {}).get("wait_for_new_source"))' not in SOURCE_TEXT
assert '"waiting_for_source": "WAITING FOR SOURCE"' in SOURCE_TEXT
assert '"identity_mismatch": "WRONG SOURCE"' in SOURCE_TEXT
assert '"WRONG SOURCE REJECTED · image and mapfile remain unchanged"' in SOURCE_TEXT
assert '"activity.hypersafe": {' in SOURCE_TEXT
assert 'activity["activity.ddrescue"] = {' in SOURCE_TEXT
assert "# Activity presentation" in SOURCE_TEXT
assert "# End Activity presentation." in SOURCE_TEXT
assert SOURCE_TEXT.count("self.run_activity_text.setPlainText(") == 1
activity_block = SOURCE_TEXT[
    SOURCE_TEXT.index("    # Activity presentation"):
    SOURCE_TEXT.index("    # End Activity presentation.")
]
assert "self.run_activity_text.setPlainText(" in activity_block
for activity_heading in (
    "ACTIVITY HEARTBEAT",
    "CURRENT OPERATION",
    "SOURCE CONDITION",
    "LAST READ PROBLEM",
    "RECOVERY",
    "LATEST OUTPUT",
    "WRITE PIPELINE",
    "LATEST EVENT",
    "PRIORITY SEARCH / PLAN",
    "PRIORITY IMAGE COVERAGE",
    "PRIORITY RECOVERY RESULT",
    "PRIORITY RETRY PASSES",
):
    assert activity_heading in activity_block

assert "# Run context presentation" in SOURCE_TEXT
assert "# End Run context presentation." in SOURCE_TEXT
run_context_block = SOURCE_TEXT[
    SOURCE_TEXT.index("    # Run context presentation"):
    SOURCE_TEXT.index("    # End Run context presentation.")
]
assert SOURCE_TEXT.count(
    "self.run_context_values[field_name].setText("
) == 1, "Run context has more than one presentation writer"
assert "self.run_context_values[field_name].setText(" in run_context_block
assert 'return ("Source", "Destination", "Mode", "Scope", "Filters")' in (
    run_context_block
)
for context_copy in (
    "Image only · ddrescue",
    "Image immediately · Hypersafe",
    "Folder Search · Hypersafe image only",
    "Tree Recovery · Hypersafe image only",
    "Folder Search · Hypersafe",
    "Tree Recovery · Hypersafe",
    "Full source · byte-sequential",
    "Existing recovered output",
    "Not used in image-only mode",
    "Not used in name mode",
):
    assert context_copy in run_context_block

assert "# Event log presentation" in SOURCE_TEXT
assert "# End Event log presentation." in SOURCE_TEXT
event_log_block = SOURCE_TEXT[
    SOURCE_TEXT.index("    # Event log presentation"):
    SOURCE_TEXT.index("    # End Event log presentation.")
]
assert SOURCE_TEXT.count("self.run_event_log.setPlainText(") == 1
assert "self.run_event_log.setPlainText(" in event_log_block
assert "Waiting for process output." in event_log_block
assert "DDRESCUE PROGRESS" in event_log_block
for gui_event_name in (
    "run_state_reused",
    "previous_run_archived",
    "read_problem",
    "state_monitor_permission",
    "kernel_io_hang",
    "monitor_error",
    "launcher_exited",
    "recovery_workers_alive",
    "process_exited",
    "done_tree_permission",
    "done_browser_error",
    "imaging_stop_requested",
    "clean_stop_requested",
    "forced_kill",
):
    assert f'event == "{gui_event_name}"' in event_log_block
for legacy_terminal_name in (
    "run_terminal",
    "_run_terminal_static_lines",
    "_run_terminal_progress_text",
    "_append_run_terminal",
    "_render_run_terminal",
    "_set_ddrescue_terminal_progress",
):
    assert legacy_terminal_name not in SOURCE_TEXT

for legacy_activity_key in (
    "operator.latest_event",
    "operator.position_heading",
    "operator.source_condition",
    "operator.priority_plan",
    "operator.priority_coverage",
    "operator.priority_result",
    "operator.priority_retries",
):
    assert legacy_activity_key not in SOURCE_TEXT
assert 'number(hypersafe, "recovered_total")' in SOURCE_TEXT
assert 'offset = rescued_bytes' in SOURCE_TEXT
assert 'selected_domain_coverage_status' in SOURCE_TEXT
assert 'selected_retry_forward_new_bytes' in SOURCE_TEXT
assert 'selected_retry_reverse_new_bytes' in SOURCE_TEXT
assert '"position_heading": "IMAGE COVERAGE"' in SOURCE_TEXT
assert 'coverage delta unavailable' in SOURCE_TEXT
assert 'Pending until MFT folder resolution' in SOURCE_TEXT
assert '"PRIORITY SEARCH / PLAN"' in SOURCE_TEXT
assert '"PRIORITY IMAGE COVERAGE"' in SOURCE_TEXT
assert '"PRIORITY RECOVERY RESULT"' in SOURCE_TEXT
assert '"PRIORITY RETRY PASSES"' in SOURCE_TEXT
assert '"WRONG SOURCE REJECTED  /  IMAGE STATE PRESERVED"' in SOURCE_TEXT
assert '"connected": "BOUND · CONNECTED"' in SOURCE_TEXT
assert 'for option in ("--hypersafe", "--hypersafe-recover")' in SOURCE_TEXT
assert 'return ["sudo", "-A"] + parts[1:], env, ""' in SOURCE_TEXT
assert 'timeout=55' in Path("scripts/carv_gui_askpass.py").read_text(encoding="utf-8")
assert "shutdown" in methods, "Source panel has no shutdown path"
assert "_shutdown_gui_workers" in methods, "main window has no shutdown coordinator"

normalizer_node = next(
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef)
    and node.name == "normalize_hypersafe_priority_terms"
)
normalizer_module = ast.fix_missing_locations(
    ast.Module(body=[normalizer_node], type_ignores=[])
)
normalizer_namespace = {}
exec(compile(normalizer_module, str(SOURCE), "exec"), normalizer_namespace)
normalize_priority_terms = normalizer_namespace[
    "normalize_hypersafe_priority_terms"
]
assert normalize_priority_terms(
    " pics \n?PICS?\n*Customer Vid*\n  project 2024  \n"
) == ["pics", "Customer Vid", "project 2024"]

decoder_node = next(
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef)
    and node.name == "decode_folder_scope_paths"
)
decoder_module = ast.fix_missing_locations(
    ast.Module(body=[decoder_node], type_ignores=[])
)
decoder_namespace = {"unquote": __import__("urllib.parse", fromlist=["unquote"]).unquote}
exec(compile(decoder_module, str(SOURCE), "exec"), decoder_namespace)
decode_scope_paths = decoder_namespace["decode_folder_scope_paths"]
assert decode_scope_paths(
    "@scope-v1:Customer%20videos%2FAVI,Project%2C%202024"
) == ["Customer videos/AVI", "Project, 2024"]

# The centralized presenter must preserve every Hypersafe Activity section.
activity_presenter_node = methods["_activity_hypersafe_presentation"]
activity_presenter_module = ast.fix_missing_locations(
    ast.Module(body=[activity_presenter_node], type_ignores=[])
)
activity_presenter_namespace = {}
exec(
    compile(activity_presenter_module, str(SOURCE), "exec"),
    activity_presenter_namespace,
)


class ActivityPresenterHarness:
    @staticmethod
    def _map_int(mapping, *keys):
        for key in keys:
            try:
                return int(mapping.get(key) or 0)
            except (TypeError, ValueError):
                continue
        return 0

    @staticmethod
    def _format_bytes(value):
        return f"{int(value)} B"


activity_presentation = activity_presenter_namespace[
    "_activity_hypersafe_presentation"
](
    ActivityPresenterHarness(),
    {
        "state": {
            "selected_files": "3",
            "selected_domain_ranges": "2",
            "selected_domain_bytes": "4096",
            "selected_domain_imaged_ranges": "1",
            "selected_domain_partial_ranges": "1",
            "selected_domain_unread_ranges": "0",
            "selected_domain_imaged_bytes": "3072",
            "selected_domain_unresolved_bytes": "1024",
            "selected_domain_coverage_status": "available",
            "selected_quick_read_status": "complete",
            "selected_quick_new_bytes": "1024",
            "selected_quick_new_bytes_known": "1",
            "quick_image_pass_status": "running",
            "selected_retry_forward_status": "pending",
            "selected_retry_reverse_status": "not_required",
            "global_retry_status": "pending",
        },
        "detail": "Reading priority extents",
        "source_status": "identity_mismatch",
        "selected": True,
        "folder_resolution_ready": True,
        "query_count": 2,
        "matched_count": 1,
        "priority_complete": 1,
        "priority_waiting": 1,
        "priority_failed": 0,
        "priority_unaccounted": 1,
        "priority_output_folders": 1,
    },
)
assert activity_presentation["position_heading"] == "IMAGE COVERAGE"
assert activity_presentation["latest_event"] == "Reading priority extents"
assert activity_presentation["source_condition"] == (
    "Wrong source rejected; no imaging resumed"
)
activity_priority_sections = dict(activity_presentation["priority_sections"])
assert set(activity_priority_sections) == {
    "PRIORITY SEARCH / PLAN",
    "PRIORITY IMAGE COVERAGE",
    "PRIORITY RECOVERY RESULT",
    "PRIORITY RETRY PASSES",
}
assert "2 search term(s)" in activity_priority_sections["PRIORITY SEARCH / PLAN"]
assert "1/2 coalesced ranges fully imaged" in activity_priority_sections[
    "PRIORITY IMAGE COVERAGE"
]
assert "1/3 complete" in activity_priority_sections["PRIORITY RECOVERY RESULT"]
assert "priority quick complete (+1024 B)" in activity_priority_sections[
    "PRIORITY RETRY PASSES"
]

fallback_activity = activity_presenter_namespace[
    "_activity_hypersafe_presentation"
](
    ActivityPresenterHarness(),
    {
        "state": {
            "priority_plan_status": "unavailable",
            "priority_plan_detail": "NTFS priority metadata unavailable",
            "selected_quick_read_status": "not_required",
            "quick_image_pass_status": "running",
            "selected_retry_forward_status": "not_required",
            "selected_retry_reverse_status": "not_required",
            "global_retry_status": "pending",
        },
        "detail": "Reading the full source image",
        "selected": True,
        "query_count": 2,
    },
)
fallback_sections = dict(fallback_activity["priority_sections"])
assert "full-source imaging continues" in fallback_sections[
    "PRIORITY SEARCH / PLAN"
]
assert "no priority extent domain was used" in fallback_sections[
    "PRIORITY IMAGE COVERAGE"
]
assert "Not attempted" in fallback_sections["PRIORITY RECOVERY RESULT"]

close_calls = {
    call_name(node)
    for node in ast.walk(methods["closeEvent"])
    if isinstance(node, ast.Call)
}
assert "self._shutdown_gui_workers" in close_calls, (
    "accepted GUI close does not quiesce background workers"
)
shutdown_source_calls = {
    call_name(node)
    for node in ast.walk(methods["_shutdown_gui_workers"])
    if isinstance(node, ast.Call)
}
assert "source_panel.shutdown" in shutdown_source_calls, (
    "main-window shutdown does not stop Source preview/prefetch work"
)
shutdown_constants = {
    node.value
    for node in ast.walk(methods["_shutdown_gui_workers"])
    if isinstance(node, ast.Constant) and isinstance(node.value, str)
}
for timer_name in (
    "_source_test_timer",
    "_hypersafe_timer",
    "_run_busy_timer",
    "_done_lazy_timer",
    "_process_timer",
):
    assert timer_name in shutdown_constants, f"shutdown omits {timer_name}"

# Setup builds the plan column before it creates SourceTreePanel.  Status
# refreshes during that construction must therefore tolerate a missing
# self.source_panel instead of crashing the whole GUI at startup.
early_source_panel_reads = [
    node
    for node in ast.walk(methods["_refresh_plan_status"])
    if isinstance(node, ast.Attribute)
    and isinstance(node.value, ast.Name)
    and node.value.id == "self"
    and node.attr == "source_panel"
]
assert not early_source_panel_reads, (
    "_refresh_plan_status assumes source_panel exists during GUI construction"
)

for method_name in sorted(GUARDED):
    recursive_calls = {
        call_name(node)
        for node in ast.walk(methods[method_name])
        if isinstance(node, ast.Call)
        and call_name(node) in {"os.walk", "_done_directory_totals"}
    }
    assert not recursive_calls, (
        f"{method_name} performs recursive filesystem work in Qt's event thread: "
        f"{sorted(recursive_calls)}"
    )

expand_blocking_calls = {
    call_name(node)
    for node in ast.walk(methods["_expand_done_recovered_item"])
    if isinstance(node, ast.Call)
    and call_name(node) in {
        "os.scandir", "iterdir", "is_dir", "is_file", "stat"
    }
}
assert not expand_blocking_calls, (
    "Done expansion performs filesystem reads in Qt's event thread: "
    f"{sorted(expand_blocking_calls)}"
)

invalidate_blocking_calls = {
    call_name(node)
    for node in ast.walk(methods["_invalidate_done_recovered_item"])
    if isinstance(node, ast.Call)
    and call_name(node) in {
        "os.scandir", "iterdir", "exists", "is_dir", "is_file", "stat"
    }
}
assert not invalidate_blocking_calls, (
    "Done collapse invalidation performs filesystem reads in Qt's event thread: "
    f"{sorted(invalidate_blocking_calls)}"
)

invalidate_node = methods["_invalidate_done_recovered_item"]
invalidate_module = ast.fix_missing_locations(
    ast.Module(body=[invalidate_node], type_ignores=[])
)


class FakeItemDataRole:
    UserRole = 100


class FakeQt:
    ItemDataRole = FakeItemDataRole


class FakeTreeItem:
    def __init__(self, values):
        self.values = dict(values)

    def data(self, column, role):
        return self.values.get((column, role))

    def setData(self, column, role, value):
        self.values[(column, role)] = value


invalidate_namespace = {"QTreeWidgetItem": FakeTreeItem, "Qt": FakeQt}
exec(compile(invalidate_module, str(SOURCE), "exec"), invalidate_namespace)


class InvalidateHarness:
    @staticmethod
    def _done_loaded_role():
        return 120

    @staticmethod
    def _done_exact_duplicate_role():
        return 121

    @staticmethod
    def _done_page_offset_role():
        return 122

    @staticmethod
    def _state_path_text(value):
        return str(value or "").strip()


invalidate = invalidate_namespace["_invalidate_done_recovered_item"]
real_directory = FakeTreeItem({(0, 100): "/out/recovered/customer", (0, 120): True})
invalidate(InvalidateHarness(), real_directory)
assert real_directory.data(0, 120) is False, (
    "collapsing a real Done directory did not invalidate its cached page"
)
exact_duplicates = FakeTreeItem({(0, 121): True, (0, 120): True})
invalidate(InvalidateHarness(), exact_duplicates)
assert exact_duplicates.data(0, 120) is True, (
    "collapsing the synthetic exact-duplicate group invalidated it"
)
next_page = FakeTreeItem({(0, 100): "/out/recovered", (0, 120): True, (0, 122): 500})
invalidate(InvalidateHarness(), next_page)
assert next_page.data(0, 120) is True, (
    "collapsing a synthetic pagination row invalidated its parent page"
)

live_refresh_calls = {
    call_name(node)
    for node in ast.walk(methods["_refresh_done_live_from_state"])
    if isinstance(node, ast.Call)
}
assert "_add_done_live_output_path" not in live_refresh_calls, (
    "live Done refresh eagerly materializes the recovered-output ledger"
)

# PyQt6 aborts the entire process when a Python exception escapes a QTimer
# callback.  Every timer connection must cross the common exception guard.
for node in ast.walk(TREE):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        continue
    if node.func.attr != "connect" or not isinstance(node.func.value, ast.Attribute):
        continue
    if node.func.value.attr != "timeout":
        continue
    assert node.args and isinstance(node.args[0], ast.Call), (
        "QTimer callback is connected without guarded_qt_timer"
    )
    assert call_name(node.args[0]) == "guarded_qt_timer", (
        "QTimer callback is connected without guarded_qt_timer"
    )

guard_node = methods["guarded_qt_timer"]
guard_module = ast.fix_missing_locations(ast.Module(body=[guard_node], type_ignores=[]))
guard_namespace = {"traceback": traceback, "sys": sys}
exec(compile(guard_module, str(SOURCE), "exec"), guard_namespace)


def timer_failure():
    raise RuntimeError("timer regression probe")


old_stderr = sys.stderr
captured_stderr = io.StringIO()
try:
    sys.stderr = captured_stderr
    result = guard_namespace["guarded_qt_timer"](
        timer_failure, "regression probe"
    )()
finally:
    sys.stderr = old_stderr
assert result is None
assert "timer regression probe" in captured_stderr.getvalue()

done_refresh_strings = {
    node.value
    for node in ast.walk(methods["_refresh_done_from_run"])
    if isinstance(node, ast.Constant) and isinstance(node.value, str)
}
assert "File findings" not in done_refresh_strings, (
    "Done summary writes a key that is not present in done_summary_values"
)
assert "Evidence" in done_refresh_strings

populate_calls = [
    node
    for node in ast.walk(methods["_populate_done_recovered_tree"])
    if isinstance(node, ast.Call)
    and isinstance(node.func, ast.Attribute)
    and node.func.attr == "setExpanded"
]
assert not populate_calls, "Done tree must not auto-expand a potentially huge output folder"

# A QTimer without an explicit positive interval defaults to 0 ms and turns
# recovery polling into a full-CPU event-loop spin.
source_text = SOURCE.read_text(encoding="utf-8")
timer_interval = re.search(
    r"self\._process_timer\.setInterval\((\d+)\)",
    source_text,
)
assert timer_interval, "recovery process timer has no explicit interval"
assert int(timer_interval.group(1)) >= 100, "recovery process timer interval is a busy spin"

# The develop timing row is useful only if the big buckets remain distinct.
classifier_node = methods["_develop_run_time_category"]
classifier_module = ast.fix_missing_locations(
    ast.Module(body=[classifier_node], type_ignores=[])
)
classifier_namespace = {}
exec(compile(classifier_module, str(SOURCE), "exec"), classifier_namespace)


class TimingHarness:
    pass


classify = classifier_namespace["_develop_run_time_category"]
timing = TimingHarness()
assert classify(
    timing,
    phase="validating Picture",
    stage={"stage": "primary_scan"},
    activity={},
) == "validation"
assert classify(
    timing,
    phase="reading disk",
    stage={"stage": "primary_scan"},
    activity={"async.queue_count": "64", "async.queue_capacity": "64"},
) == "output_wait"
assert classify(
    timing,
    phase="Reading HFS+ Catalog",
    stage={"stage": "primary_metadata_bootstrap"},
    activity={},
) == "metadata"
assert classify(
    timing,
    phase="reading disk",
    stage={"stage": "primary_scan"},
    activity={},
) == "source"
assert classify(
    timing,
    phase="resume loading",
    stage={"stage": "resume_loading"},
    activity={},
) == "restart_other"

# Exercise the real TSV reader without importing Qt: unchanged files must
# reuse parsed rows and append-only evidence must parse only its new tail.
reader_node = methods["_read_tsv_rows"]
reader_module = ast.fix_missing_locations(ast.Module(body=[reader_node], type_ignores=[]))
reader_namespace = {"Path": Path, "csv": csv, "re": re}
exec(compile(reader_module, str(SOURCE), "exec"), reader_namespace)


class ReaderHarness:
    pass


reader = ReaderHarness()
reader._tsv_rows_cache = {}
with tempfile.TemporaryDirectory(prefix="carv-gui-tsv-") as temp_dir:
    evidence = Path(temp_dir) / "gui_recovery_evidence.tsv"
    evidence.write_text(
        "pass_id\tgeometry\tstart_offset\tend_offset\tkind\tconfidence\toutput_count\n"
        "p0001\tspan\t10\t20\trecovered\texact\t1\n",
        encoding="ascii",
    )
    fields = (
        "pass_id", "geometry", "start_offset", "end_offset", "kind",
        "confidence", "output_count",
    )
    first = reader_namespace["_read_tsv_rows"](reader, evidence, fields)
    unchanged = reader_namespace["_read_tsv_rows"](reader, evidence, fields)
    assert unchanged is first and len(first) == 1, "unchanged TSV was reparsed"
    with evidence.open("a", encoding="ascii") as handle:
        handle.write("p0001\tspan\t30\t40\trecovered\texact\t1\n")
    appended = reader_namespace["_read_tsv_rows"](reader, evidence, fields)
    assert len(appended) == 2 and appended[0] is first[0], "TSV tail was not incremental"
    assert appended[1]["start_offset"] == "30"

# Live recovery evidence can contain hundreds of thousands of rows.  The GUI
# must consume only the appended tail and keep a bounded display model instead
# of handing every raw row to the paint event.
segment_node = next(
    node for node in TREE.body
    if isinstance(node, ast.ClassDef) and node.name == "DiskMapSegment"
)
modern_nodes = [
    methods["_evidence_bucket_width"],
    methods["_read_modern_recovery_segments"],
]
modern_module = ast.fix_missing_locations(
    ast.Module(body=[segment_node] + modern_nodes, type_ignores=[])
)
modern_namespace = {
    "dataclass": dataclass,
    "Path": Path,
}
exec(compile(modern_module, str(SOURCE), "exec"), modern_namespace)


class ModernEvidenceHarness:
    def __init__(self):
        self._modern_recovery_evidence_cache = None

    @staticmethod
    def _evidence_artifact(state_dir, name):
        return state_dir / name

    @staticmethod
    def _path_stat(path):
        try:
            return path.stat()
        except OSError:
            return None

    _evidence_bucket_width = staticmethod(
        modern_namespace["_evidence_bucket_width"]
    )


with tempfile.TemporaryDirectory(prefix="carv-gui-modern-") as temp_dir:
    state_dir = Path(temp_dir)
    evidence = state_dir / "gui_recovery_evidence.tsv"
    with evidence.open("w", encoding="ascii") as handle:
        handle.write(
            "pass_id\tgeometry\tstart_offset\tend_offset\tkind\tconfidence\toutput_count\n"
        )
        for offset in range(20_000):
            handle.write(
                f"p0001\tpoint\t{offset}\t{offset}\trecovered\tmarker\t1\n"
            )
    modern = ModernEvidenceHarness()
    segments, count = modern_namespace["_read_modern_recovery_segments"](
        modern,
        state_dir,
        100_000,
    )
    assert count == 20_000
    assert len(segments) <= 4096, "live evidence display was not bounded"
    old_position = modern._modern_recovery_evidence_cache["position"]
    with evidence.open("a", encoding="ascii") as handle:
        handle.write("p0001\tpoint\t90000\t90000\trecovered\tmarker\t3\n")
    segments, count = modern_namespace["_read_modern_recovery_segments"](
        modern,
        state_dir,
        100_000,
    )
    assert count == 20_003
    assert modern._modern_recovery_evidence_cache["position"] > old_position
    assert len(segments) <= 4096

# The partial-image escape hatch is intentionally narrow: it is visible while
# Hypersafe is reading the whole source, but not during its metadata or selected
# folder passes.  A stale status file from an earlier pass must not hide it.
continue_button_node = methods["_update_continue_image_button"]
continue_button_module = ast.fix_missing_locations(
    ast.Module(body=[continue_button_node], type_ignores=[])
)
continue_button_namespace = {"Path": Path}
exec(
    compile(continue_button_module, str(SOURCE), "exec"),
    continue_button_namespace,
)


class ContinueButtonProbe:
    def __init__(self):
        self.visible = None
        self.enabled = None
        self.text = ""

    def setVisible(self, value):
        self.visible = bool(value)

    def setEnabled(self, value):
        self.enabled = bool(value)

    def setText(self, value):
        self.text = str(value)

    def setToolTip(self, value):
        self.tooltip = str(value)


class LiveProcessProbe:
    @staticmethod
    def poll():
        return None


class ContinueImageHarness:
    def __init__(self):
        self.continue_image_button = ContinueButtonProbe()
        self._process = LiveProcessProbe()
        self._run_command_parts = ["--hypersafe-recover"]
        self._run_requested_make_image_first = True
        self._continue_image_requested = False

    @staticmethod
    def _read_state_file(_path):
        return {"status": "failed"}

    @staticmethod
    def _path_exists(_path):
        return False


update_continue_button = continue_button_namespace["_update_continue_image_button"]
continue_harness = ContinueImageHarness()
update_continue_button(
    continue_harness,
    Path("state"),
    {},
    {"stage": "waiting_for_source"},
    {"status": "active", "continue_available": "1"},
    True,
)
assert continue_harness.continue_image_button.visible is True
assert continue_harness.continue_image_button.enabled is True
assert continue_harness.continue_image_button.text == (
    "STOP IMAGING · RECOVER FROM IMAGE"
)

update_continue_button(
    continue_harness,
    Path("state"),
    {},
    {"stage": "early_selected_recovery"},
    {"status": "active", "continue_available": "0"},
    True,
)
assert continue_harness.continue_image_button.visible is True
assert continue_harness.continue_image_button.enabled is True
assert continue_harness.continue_image_button.text == "STOP DDRESCUE · SAVE MAP"

update_continue_button(
    continue_harness,
    Path("state"),
    {},
    {"stage": "early_selected_recovery"},
    {},
    False,
)
assert continue_harness.continue_image_button.visible is False

source_text = SOURCE.read_text(encoding="utf-8")
assert "skip the remaining source retries in this run" in source_text
assert "revisited with Resume later" in source_text

print("GUI event-thread filesystem safety checks passed")
