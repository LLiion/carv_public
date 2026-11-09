#
# Main build for the native `carv` binary.
# Keep the default target portable, and provide a small Ubuntu-specific
# entry point that avoids inheriting host-local compiler/linker flags.
#

CC ?= cc
PYTHON ?= python3
PYINSTALLER ?= pyinstaller
OPTFLAGS ?= -O2
DEPFLAGS ?= -MMD -MP
THREAD_FLAGS ?= -pthread
CARV_VERSION ?= 0.0.1
PROJECT_ROOT := $(abspath .)

# Preserve first-seen order while dropping exact duplicate tokens inherited
# from host-local shell environments.
uniq_words = $(if $(strip $1),$(firstword $1) $(call uniq_words,$(filter-out $(firstword $1),$1)))

JPEG_ENABLED ?= auto
JPEG_DETECTED := $(shell pkg-config --exists libjpeg 2>/dev/null && echo 1 || echo 0)
ifeq ($(JPEG_ENABLED),1)
JPEG_ENABLED_VALUE := 1
else ifeq ($(JPEG_ENABLED),0)
JPEG_ENABLED_VALUE := 0
else
JPEG_ENABLED_VALUE := $(JPEG_DETECTED)
endif
ifeq ($(JPEG_ENABLED_VALUE),1)
JPEG_CFLAGS ?= $(shell pkg-config --cflags libjpeg 2>/dev/null || true)
JPEG_LIBS ?= $(shell pkg-config --libs libjpeg 2>/dev/null || echo -ljpeg)
JPEG_FEATURE_NOTE = @:
else
JPEG_CFLAGS :=
JPEG_LIBS :=
JPEG_FEATURE_NOTE = @printf '%s\n' "Building without libjpeg; JPEG recovery and JPEG fragment repair are disabled. Install libjpeg-dev for full JPEG support."
endif
CPPFLAGS += -DCARVER_HAVE_LIBJPEG=$(JPEG_ENABLED_VALUE)
CPPFLAGS += -DCARV_VERSION='"$(CARV_VERSION)"'
CFLAGS += $(OPTFLAGS) $(DEPFLAGS) -Wall -Wextra -Wpedantic -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 -Iinclude $(THREAD_FLAGS)
CFLAGS += $(JPEG_CFLAGS)
LDLIBS += -lsqlite3 $(THREAD_FLAGS)
LDLIBS += $(JPEG_LIBS)
CPPFLAGS := $(call uniq_words,$(CPPFLAGS))
CFLAGS := $(call uniq_words,$(CFLAGS))
LDFLAGS := $(call uniq_words,$(LDFLAGS))
LDLIBS := $(call uniq_words,$(LDLIBS))

TARGET = carv
GUI_LAUNCHER = carv_gui
GUI_TERMINAL_LAUNCHER = carv_gui_terminal
GUI_DIST_LAUNCHER = carv_gui
GUI_SCRIPT = scripts/carv_gui_qt.py
GUI_ASKPASS = scripts/carv_gui_askpass.py
GUI_DESKTOP_DEV_MANAGER = scripts/manage_linux_desktop_dev.py
GUI_USER_INSTALL_MANAGER = scripts/manage_linux_user_install.py
GUI_COMBO_ARROW = scripts/combo_down_v.svg
GUI_COMBO_ARROW_MACOS = scripts/combo_down_v_macos.svg
GUI_TREE_BRANCH_CLOSED_BLACK = scripts/tree_branch_closed_black.svg
GUI_TREE_BRANCH_OPEN_BLACK = scripts/tree_branch_open_black.svg
GUI_TREE_BRANCH_CLOSED_WHITE = scripts/tree_branch_closed_white.svg
GUI_TREE_BRANCH_OPEN_WHITE = scripts/tree_branch_open_white.svg
GUI_WRENCH_ICON = scripts/wrench_button_icon.png
GUI_TITLE_LOGO = scripts/carv_title_logo.png
DESKTOP_LAUNCHER_BUILD = scripts/write_linux_desktop_launcher.py
USER_INSTALLER = install-carv.sh
USER_UNINSTALLER = uninstall-carv.sh
BUNDLE_DIR ?= dist/carv
RUNTIME_BUNDLE_ARCHIVE ?= dist/carv-$(CARV_VERSION)-ubuntu-x86_64.tar.gz
RUNTIME_BUNDLE_SHA256 ?= $(RUNTIME_BUNDLE_ARCHIVE).sha256
LINUX_RUN_INSTALLER ?= dist/Carv-$(CARV_VERSION)-Ubuntu-x86_64.run
LINUX_RUN_INSTALLER_SHA256 ?= $(LINUX_RUN_INSTALLER).sha256
DEB_ARCH ?= amd64
DEB_PACKAGE ?= dist/carv_$(CARV_VERSION)_$(DEB_ARCH).deb
DEB_PACKAGE_SHA256 ?= $(DEB_PACKAGE).sha256
PYINSTALLER_NAME ?= Carv
PYINSTALLER_DIST_DIR ?= dist
PYINSTALLER_WORK_DIR ?= build/pyinstaller
PYINSTALLER_SPEC_DIR ?= build/pyinstaller-spec
PYINSTALLER_ONEFILE_DIR ?= dist/Carv-onefile
PYINSTALLER_BUNDLE_ARCHIVE ?= dist/Carv-ubuntu-x86_64.tar.gz
PYINSTALLER_ONEFILE_ARCHIVE ?= dist/Carv-onefile-ubuntu-x86_64.tar.gz
RUNTIME_DATA = data/database.db
PYINSTALLER_DATA_ARGS = $(foreach file,$(RUNTIME_DATA),--add-data "$(PROJECT_ROOT)/$(file):data")
GUI_RUNTIME_FILES = \
	$(GUI_SCRIPT) \
	$(GUI_ASKPASS) \
	$(GUI_DESKTOP_DEV_MANAGER) \
	$(GUI_USER_INSTALL_MANAGER) \
	$(GUI_COMBO_ARROW) \
	$(GUI_COMBO_ARROW_MACOS) \
	$(GUI_TREE_BRANCH_CLOSED_BLACK) \
	$(GUI_TREE_BRANCH_OPEN_BLACK) \
	$(GUI_TREE_BRANCH_CLOSED_WHITE) \
	$(GUI_TREE_BRANCH_OPEN_WHITE) \
	$(GUI_WRENCH_ICON) \
	$(GUI_TITLE_LOGO)
SRC = \
	src/main.c \
	src/app.c \
	src/app_resume_state.c \
	src/config.c \
	src/platform.c \
	src/probe.c \
	src/log.c \
	src/db.c \
	src/blob_start.c \
	src/magic_db.c \
	src/magic.c \
	src/hex.c \
	src/reader.c \
	src/scan_state.c \
	src/ddrescue_map.c \
	src/ddrescue_supervisor.c \
	src/ntfs_hypersafe.c \
	src/raw_all_selection.c \
	src/matcher.c \
	src/container_context.c \
	src/format_pipeline.c \
	src/fs_backend.c \
	src/filtered_image_log.c \
	src/image_triage.c \
	src/recovered_content_index.c \
	src/exfat_backend.c \
	src/hfsplus_backend.c \
	src/mft_engine.c \
	src/mft_background.c \
	src/mft_spool.c \
	src/metadata_index.c \
	src/metadata_outcome.c \
	src/mft_runlist.c \
	src/recovery_runner.c \
	src/carver_output.c \
	src/carver_output_async.c \
	src/carver_archive.c \
	src/carver_audio.c \
	src/carver_cfb.c \
	src/jpeg_stream_probe.c \
	src/jpeg_mpf_parser.c \
	src/jpeg_wrapper_classifier.c \
	src/raw_candidate_stream.c \
	src/carver_jpeg.c \
	src/carver_png.c \
	src/carver_gif.c \
	src/carver_pdf.c \
	src/carver_sqlite.c \
	src/carver_tiff.c \
	src/carver_jp2.c \
	src/carver_psd.c \
	src/carver_raw.c \
	src/carver_zip.c \
	src/carver_riff.c \
	src/video_validation.c \
	src/carver_mov.c \
	src/carver_mpeg_ps.c \
	src/carver_mkv.c \
	src/carver_bmp.c \
	src/scanner.c \
	src/mft.c \
	src/mftprobe_embedded.c \
	src/mftprobe_format_api.c \
	src/mftprobe_format_jpeg_recovery.c \
	src/mftprobe_format_registry.c \
	src/mftprobe_format_jpeg_validator.c \
	src/mftprobe_format_riff_validator.c \
	src/mftprobe_engine.c \
	src/mftprobe_users_tree.c \
	src/mft_probe_parser.c

OBJ = $(SRC:.c=.o)
DEP = $(OBJ:.o=.d)

all: $(TARGET)

gui-check:
	PYTHONPYCACHEPREFIX=/tmp/carv-pycache $(PYTHON) -m py_compile $(GUI_SCRIPT) $(GUI_ASKPASS)
	@if test -f tests/test_gui_event_thread_safety.py; then \
		$(PYTHON) tests/test_gui_event_thread_safety.py; \
	else \
		echo "GUI event-thread regression check skipped (development tests not installed)"; \
	fi

metadata-index-check:
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_metadata_index.c src/metadata_index.c src/metadata_outcome.c -o /tmp/carv-metadata-index-check
	/tmp/carv-metadata-index-check

image-triage-check:
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_image_triage.c src/image_triage.c -o /tmp/carv-image-triage-check
	/tmp/carv-image-triage-check

content-index-check:
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_recovered_content_index.c src/recovered_content_index.c -o /tmp/carv-content-index-check -lsqlite3
	/tmp/carv-content-index-check

scope-list-check:
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_scope_list.c src/config.c -o /tmp/carv-scope-list-check
	/tmp/carv-scope-list-check

hfsplus-fixture-check:
	PYTHONPYCACHEPREFIX=/tmp/carv-pycache $(PYTHON) tests/test_hfsplus_fixture.py

ntfs-hypersafe-fixture-check: $(TARGET)
	PYTHONPYCACHEPREFIX=/tmp/carv-pycache $(PYTHON) tests/test_hypersafe_dispatch_contract.py
	PYTHONPYCACHEPREFIX=/tmp/carv-pycache $(PYTHON) tests/test_ntfs_hypersafe_fixture.py

postscan-contract-check:
	PYTHONPYCACHEPREFIX=/tmp/carv-pycache $(PYTHON) tests/test_raw_all_postscan_contract.py

scan-state-check:
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_scan_state.c src/scan_state.c -o /tmp/carv-scan-state-check
	/tmp/carv-scan-state-check

ddrescue-supervisor-check:
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_ddrescue_supervisor.c src/ddrescue_supervisor.c -o /tmp/carv-ddrescue-supervisor-check
	/tmp/carv-ddrescue-supervisor-check

user-install-check:
	PYTHONPYCACHEPREFIX=/tmp/carv-pycache $(PYTHON) tests/test_linux_user_install.py

release-check: gui-check metadata-index-check image-triage-check \
	content-index-check scope-list-check hfsplus-fixture-check \
	ntfs-hypersafe-fixture-check postscan-contract-check scan-state-check \
	ddrescue-supervisor-check user-install-check

check-ubuntu-release-host:
	@test "$$(uname -s)" = "Linux" || { \
		echo "Ubuntu release packages must be built on Linux, not $$(uname -s)." >&2; \
		exit 2; \
	}
	@test "$$(uname -m)" = "x86_64" || { \
		echo "This pre-release target requires x86_64, not $$(uname -m)." >&2; \
		exit 2; \
	}
	@command -v dpkg-deb >/dev/null 2>&1 || { \
		echo "dpkg-deb is required to build the Ubuntu package." >&2; \
		exit 2; \
	}
	@test "$$(dpkg --print-architecture)" = "amd64" || { \
		echo "This pre-release target requires Debian architecture amd64." >&2; \
		exit 2; \
	}

hfsplus-extent-report:
	@test -n "$(INDEX_DIR)" || { echo "usage: make hfsplus-extent-report INDEX_DIR=/path/to/state/metadata/index" >&2; exit 2; }
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/hfsplus_extent_report.c src/metadata_index.c src/metadata_outcome.c -o /tmp/carv-hfsplus-extent-report
	/tmp/carv-hfsplus-extent-report "$(INDEX_DIR)"

gui: $(TARGET) gui-check
	./$(GUI_LAUNCHER)

desktop-dev-install: gui-check
	$(PYTHON) $(GUI_DESKTOP_DEV_MANAGER) install "$(PROJECT_ROOT)"

desktop-dev-uninstall:
	$(PYTHON) $(GUI_DESKTOP_DEV_MANAGER) remove

install-user: bundle
	$(BUNDLE_DIR)/$(USER_INSTALLER)

uninstall-user:
	$(PYTHON) $(GUI_USER_INSTALL_MANAGER) remove

# Rebuild from a cleaner Linux-like baseline so local macOS env flags
# do not accidentally hide Ubuntu build issues.
ubuntu-build: check-ubuntu-release-host
	CPPFLAGS= CFLAGS= LDFLAGS= $(MAKE) clean CC=gcc
	CPPFLAGS= CFLAGS= LDFLAGS= $(MAKE) all CC=gcc
	$(MAKE) postscan-contract-check

ubuntu-release: check-ubuntu-release-host
	$(MAKE) ubuntu-build
	$(MAKE) release-check
	$(MAKE) release

$(TARGET): $(OBJ)
	$(JPEG_FEATURE_NOTE)
	$(CC) $(LDFLAGS) $(OBJ) -o $(TARGET) $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# The version is defined in this Makefile. Rebuild the two objects that embed
# it whenever that definition changes, even if their C sources did not.
src/app.o src/config.o: Makefile

bundle: $(TARGET) $(RUNTIME_DATA) $(GUI_USER_INSTALL_MANAGER)
	rm -rf $(BUNDLE_DIR)
	rm -f $(dir $(BUNDLE_DIR))$(GUI_TERMINAL_LAUNCHER) $(dir $(BUNDLE_DIR))$(GUI_DIST_LAUNCHER)
	mkdir -p $(BUNDLE_DIR)/data $(BUNDLE_DIR)/scripts
	cp $(TARGET) $(BUNDLE_DIR)/
	cp $(GUI_LAUNCHER) $(BUNDLE_DIR)/
	cp $(GUI_TERMINAL_LAUNCHER) $(BUNDLE_DIR)/
	@printf '%s\n' "$(CARV_VERSION)" > $(BUNDLE_DIR)/VERSION
	$(PYTHON) $(GUI_USER_INSTALL_MANAGER) write-wrappers $(BUNDLE_DIR)
	cp $(GUI_TERMINAL_LAUNCHER) $(dir $(BUNDLE_DIR))$(GUI_DIST_LAUNCHER)
	cp $(RUNTIME_DATA) $(BUNDLE_DIR)/data/
	cp $(GUI_RUNTIME_FILES) $(BUNDLE_DIR)/scripts/
	chmod +x $(BUNDLE_DIR)/$(GUI_LAUNCHER) $(BUNDLE_DIR)/$(GUI_TERMINAL_LAUNCHER) $(BUNDLE_DIR)/$(USER_INSTALLER) $(BUNDLE_DIR)/$(USER_UNINSTALLER) $(dir $(BUNDLE_DIR))$(GUI_DIST_LAUNCHER) $(BUNDLE_DIR)/scripts/carv_gui_qt.py $(BUNDLE_DIR)/scripts/carv_gui_askpass.py $(BUNDLE_DIR)/scripts/manage_linux_user_install.py
	@printf '%s\n' "Bundled Carv $(CARV_VERSION) runtime with Qt GUI launcher created in $(BUNDLE_DIR)"

bundle-archive: check-ubuntu-release-host bundle
	rm -f $(RUNTIME_BUNDLE_ARCHIVE) $(RUNTIME_BUNDLE_SHA256)
	tar -C $(dir $(BUNDLE_DIR)) -czf $(RUNTIME_BUNDLE_ARCHIVE) $(notdir $(BUNDLE_DIR)) $(GUI_DIST_LAUNCHER)
	@if command -v sha256sum >/dev/null 2>&1; then \
		cd $(dir $(RUNTIME_BUNDLE_ARCHIVE)) && sha256sum $(notdir $(RUNTIME_BUNDLE_ARCHIVE)) > $(notdir $(RUNTIME_BUNDLE_SHA256)); \
	else \
		cd $(dir $(RUNTIME_BUNDLE_ARCHIVE)) && shasum -a 256 $(notdir $(RUNTIME_BUNDLE_ARCHIVE)) > $(notdir $(RUNTIME_BUNDLE_SHA256)); \
	fi
	@printf '%s\n' "Runtime bundle archive: $(RUNTIME_BUNDLE_ARCHIVE)"
	@printf '%s\n' "SHA-256 checksum:      $(RUNTIME_BUNDLE_SHA256)"

installer: check-ubuntu-release-host bundle
	rm -f $(LINUX_RUN_INSTALLER) $(LINUX_RUN_INSTALLER_SHA256)
	$(PYTHON) $(GUI_USER_INSTALL_MANAGER) build-run $(BUNDLE_DIR) $(LINUX_RUN_INSTALLER) $(CARV_VERSION)
	@if command -v sha256sum >/dev/null 2>&1; then \
		cd $(dir $(LINUX_RUN_INSTALLER)) && sha256sum $(notdir $(LINUX_RUN_INSTALLER)) > $(notdir $(LINUX_RUN_INSTALLER_SHA256)); \
	else \
		cd $(dir $(LINUX_RUN_INSTALLER)) && shasum -a 256 $(notdir $(LINUX_RUN_INSTALLER)) > $(notdir $(LINUX_RUN_INSTALLER_SHA256)); \
	fi
	@printf '%s\n' "Single-file installer: $(LINUX_RUN_INSTALLER)"
	@printf '%s\n' "SHA-256 checksum:     $(LINUX_RUN_INSTALLER_SHA256)"

deb: check-ubuntu-release-host bundle
	rm -f $(DEB_PACKAGE) $(DEB_PACKAGE_SHA256)
	$(PYTHON) $(GUI_USER_INSTALL_MANAGER) build-deb $(BUNDLE_DIR) $(DEB_PACKAGE) $(CARV_VERSION) $(DEB_ARCH)
	@if command -v sha256sum >/dev/null 2>&1; then \
		cd $(dir $(DEB_PACKAGE)) && sha256sum $(notdir $(DEB_PACKAGE)) > $(notdir $(DEB_PACKAGE_SHA256)); \
	else \
		cd $(dir $(DEB_PACKAGE)) && shasum -a 256 $(notdir $(DEB_PACKAGE)) > $(notdir $(DEB_PACKAGE_SHA256)); \
	fi
	@printf '%s\n' "Clickable Ubuntu package: $(DEB_PACKAGE)"
	@printf '%s\n' "SHA-256 checksum:        $(DEB_PACKAGE_SHA256)"

release: bundle-archive installer deb

pyinstaller-bundle: $(TARGET) gui-check $(RUNTIME_DATA)
	rm -rf $(PYINSTALLER_DIST_DIR)/$(PYINSTALLER_NAME)
	mkdir -p $(PYINSTALLER_WORK_DIR) $(PYINSTALLER_SPEC_DIR)
	$(PYINSTALLER) \
		--noconfirm \
		--clean \
		--name $(PYINSTALLER_NAME) \
		--onedir \
		--windowed \
		--distpath $(PYINSTALLER_DIST_DIR) \
		--workpath $(PYINSTALLER_WORK_DIR) \
		--specpath $(PYINSTALLER_SPEC_DIR) \
		--add-binary "$(PROJECT_ROOT)/$(TARGET):." \
		$(PYINSTALLER_DATA_ARGS) \
		--add-data "$(PROJECT_ROOT)/$(GUI_ASKPASS):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_COMBO_ARROW):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_COMBO_ARROW_MACOS):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_TREE_BRANCH_CLOSED_BLACK):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_TREE_BRANCH_OPEN_BLACK):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_TREE_BRANCH_CLOSED_WHITE):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_TREE_BRANCH_OPEN_WHITE):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_WRENCH_ICON):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_TITLE_LOGO):scripts" \
		$(GUI_SCRIPT)
	chmod +x $(PYINSTALLER_DIST_DIR)/$(PYINSTALLER_NAME)/$(PYINSTALLER_NAME)
	$(PYTHON) $(DESKTOP_LAUNCHER_BUILD) $(PYINSTALLER_DIST_DIR)/$(PYINSTALLER_NAME) $(PYINSTALLER_NAME)
	@printf '%s\n' "PyInstaller GUI bundle created in $(PYINSTALLER_DIST_DIR)/$(PYINSTALLER_NAME)"

pyinstaller-onefile: $(TARGET) gui-check $(RUNTIME_DATA)
	rm -rf $(PYINSTALLER_ONEFILE_DIR)
	mkdir -p $(PYINSTALLER_ONEFILE_DIR) $(PYINSTALLER_WORK_DIR)-onefile $(PYINSTALLER_SPEC_DIR)-onefile
	$(PYINSTALLER) \
		--noconfirm \
		--clean \
		--name $(PYINSTALLER_NAME) \
		--onefile \
		--windowed \
		--distpath $(PYINSTALLER_ONEFILE_DIR) \
		--workpath $(PYINSTALLER_WORK_DIR)-onefile \
		--specpath $(PYINSTALLER_SPEC_DIR)-onefile \
		--add-binary "$(PROJECT_ROOT)/$(TARGET):." \
		$(PYINSTALLER_DATA_ARGS) \
		--add-data "$(PROJECT_ROOT)/$(GUI_ASKPASS):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_COMBO_ARROW):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_COMBO_ARROW_MACOS):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_TREE_BRANCH_CLOSED_BLACK):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_TREE_BRANCH_OPEN_BLACK):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_TREE_BRANCH_CLOSED_WHITE):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_TREE_BRANCH_OPEN_WHITE):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_WRENCH_ICON):scripts" \
		--add-data "$(PROJECT_ROOT)/$(GUI_TITLE_LOGO):scripts" \
		$(GUI_SCRIPT)
	chmod +x $(PYINSTALLER_ONEFILE_DIR)/$(PYINSTALLER_NAME)
	$(PYTHON) $(DESKTOP_LAUNCHER_BUILD) $(PYINSTALLER_ONEFILE_DIR) $(PYINSTALLER_NAME)
	@printf '%s\n' "PyInstaller one-file GUI executable created at $(PYINSTALLER_ONEFILE_DIR)/$(PYINSTALLER_NAME)"

pyinstaller-archives: pyinstaller-bundle pyinstaller-onefile
	rm -f $(PYINSTALLER_BUNDLE_ARCHIVE) $(PYINSTALLER_ONEFILE_ARCHIVE)
	tar -C $(PYINSTALLER_DIST_DIR) -czf $(PYINSTALLER_BUNDLE_ARCHIVE) $(PYINSTALLER_NAME)
	tar -C $(PYINSTALLER_DIST_DIR) -czf $(PYINSTALLER_ONEFILE_ARCHIVE) $(notdir $(PYINSTALLER_ONEFILE_DIR))
	@printf '%s\n' "PyInstaller archives created:"
	@printf '  %s\n' "$(PYINSTALLER_BUNDLE_ARCHIVE)"
	@printf '  %s\n' "$(PYINSTALLER_ONEFILE_ARCHIVE)"

clean:
	rm -f $(OBJ) $(DEP) $(TARGET)
	rm -rf scripts/__pycache__

re: clean all

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean re run gui gui-check desktop-dev-install desktop-dev-uninstall \
	install-user uninstall-user user-install-check metadata-index-check \
	image-triage-check content-index-check scope-list-check hfsplus-fixture-check \
	ntfs-hypersafe-fixture-check postscan-contract-check scan-state-check \
	ddrescue-supervisor-check hfsplus-extent-report release-check \
	check-ubuntu-release-host ubuntu-build ubuntu-release bundle bundle-archive \
	installer deb release pyinstaller-bundle pyinstaller-onefile \
	pyinstaller-archives

-include $(DEP)
