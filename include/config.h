/*
 * config.h
 * Stores application configuration values.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>

#ifndef CARV_VERSION
#define CARV_VERSION "development"
#endif

#ifdef __APPLE__
#define APP_DEFAULT_OUTPUT_DIR "/media/eh/out"
#else
#define APP_DEFAULT_OUTPUT_DIR "./saved"
#endif
#define APP_RECOVERED_DIR_NAME "recovered"
#define APP_STATE_DIR_NAME "state"
#define APP_SPOOL_DIR_NAME "spool"
#define APP_INDEX_DIR_NAME "index"
#define APP_PHOTOREC_IMPORT_DIR_NAME "pr"
#define APP_UNIDENT_DIR_NAME "Unidentified"
#define APP_PARTIAL_TREE_DIR_NAME "Partial_tree"
#define APP_DELETED_DIR_NAME "Deleted"
#define APP_LEGACY_UNIDENT_DIR_NAME "unident"
#define APP_LEGACY_PARTIAL_TREE_DIR_NAME "partial_tree"
#define APP_PHOTOREC_IMPORT_RELATIVE_DIR APP_RECOVERED_DIR_NAME "/" APP_PHOTOREC_IMPORT_DIR_NAME
#define APP_UNIDENT_RELATIVE_DIR APP_RECOVERED_DIR_NAME "/" APP_UNIDENT_DIR_NAME
#define APP_PARTIAL_TREE_RELATIVE_DIR APP_RECOVERED_DIR_NAME "/" APP_PARTIAL_TREE_DIR_NAME
#define APP_DELETED_RELATIVE_DIR APP_RECOVERED_DIR_NAME "/" APP_DELETED_DIR_NAME
#define APP_LEGACY_UNIDENT_RELATIVE_DIR APP_RECOVERED_DIR_NAME "/" APP_LEGACY_UNIDENT_DIR_NAME
#define APP_LEGACY_PARTIAL_TREE_RELATIVE_DIR APP_RECOVERED_DIR_NAME "/" APP_LEGACY_PARTIAL_TREE_DIR_NAME
#define APP_DEFAULT_UNIDENT_DIR APP_DEFAULT_OUTPUT_DIR "/" APP_UNIDENT_RELATIVE_DIR
#define APP_STATE_RELATIVE_DIR APP_STATE_DIR_NAME
#define APP_DEFAULT_STATE_DIR APP_DEFAULT_OUTPUT_DIR "/" APP_STATE_RELATIVE_DIR
#define APP_SPOOL_RELATIVE_DIR APP_STATE_DIR_NAME "/" APP_SPOOL_DIR_NAME
#define APP_INDEX_RELATIVE_DIR APP_STATE_DIR_NAME "/" APP_INDEX_DIR_NAME
#define APP_DEFAULT_SPOOL_DIR APP_DEFAULT_OUTPUT_DIR "/" APP_SPOOL_RELATIVE_DIR
#define APP_DEFAULT_INDEX_DIR APP_DEFAULT_OUTPUT_DIR "/" APP_INDEX_RELATIVE_DIR

/*
 * Temporary maintenance mode:
 * keep MFT tree building active, but skip file carving until the
 * directory/MFT issues are fully resolved.
 * Set to 0 to restore normal recovery paths.
 */
#ifndef TEMP_TREE_ONLY_MODE
#define TEMP_TREE_ONLY_MODE 0
#endif

typedef enum {
    APP_SCAN_MODE_MFT_USERS = 0,
    APP_SCAN_MODE_RAW_ALL = 1,
    APP_SCAN_MODE_COMPARE = 2
} AppScanMode;

typedef enum {
    APP_IMAGE_DDRESCUE_MODE_BASIC = 0,
    APP_IMAGE_DDRESCUE_MODE_THOROUGH = 1
} AppImageDdrescueMode;

typedef enum {
    APP_FILESYSTEM_TARGET_AUTO = 0,
    APP_FILESYSTEM_TARGET_NTFS = 1,
    APP_FILESYSTEM_TARGET_HFSPLUS = 2
} AppFilesystemTarget;

typedef enum {
    APP_HYPERSAFE_STRATEGY_NONE = 0,
    APP_HYPERSAFE_STRATEGY_IMAGE_IMMEDIATELY = 1,
    APP_HYPERSAFE_STRATEGY_SELECTED_FOLDERS = 2
} AppHypersafeStrategy;

#define APP_AUTO_NAME_AFTER_ALL_DEFAULT  (-1)
#define APP_AUTO_NAME_AFTER_ALL_EXPLICIT 1

typedef struct {
    const char *input_path;
    const char *db_path;
    size_t chunk_size;

    const char *source_path;
    const char *image_path;
    const char *output_dir;
    const char *run_name;
    const char *compare_mount_path;
    const char *compare_scope_csv;
    const char *record_list_path;
    const char *target_filter_csv;
    const char *root_scope_csv;
    int root_scope_defaulted;
    const char *target_date_value;
    const char *target_find_value;
    const char *target_deleted_value;
    int target_folder_levels;
    const char *mft_categories_csv;
    const char *mft_formats_csv;
    const char *mft_dev_format;
    unsigned long long mft_limit;
    int metadata_test_jpegs;
    unsigned int metadata_test_jpeg_count;
    AppScanMode scan_mode;

    int recover_img;
    int recover_vid;
    int recover_doc;
    int auto_recover_missed;
    int only_recover_missed;
    int auto_name_after_all;
    int name_only;
    int make_image_first;
    int image_only;
    unsigned long long image_size_bytes;
    int recovery_nap_enabled;
    int recovery_nap_power_cycle;
    unsigned int recovery_nap_minutes;
    unsigned int recovery_nap_cycles;
    unsigned int recovery_nap_test_after_seconds;
    AppImageDdrescueMode image_ddrescue_mode;
    AppFilesystemTarget filesystem_target;
    int mft_path_requested;
    int skip_mft_observation;
    int quick_resume;
    int additive_pass;
    int additive_requested;
    int additive_auto_selection;
    int resume_active;
    int resume_completed;
    int resume_scan_completed;
    int crash_retries;
    int stall_retries;
    unsigned long long resume_offset;
    unsigned long long manual_start_offset;
    unsigned long long crash_retry_skip_bytes;
    unsigned long long stall_timeout_seconds;
    unsigned long long stall_retry_backtrack_bytes;
    double target_mib_per_sec;
    int manual_start_explicit;
    const char *scan_state_path;
    int record_list_auto;
    int list_formats;
    int list_root_folders;
    const char *list_folders_under;
    int hypersafe_folder_fetch;
    AppHypersafeStrategy hypersafe_strategy;
    const char *hypersafe_preview_status_path;
    int probe_source;
    int input_explicit;
    int show_help;
    int verbose;
    char root_scope_csv_storage[4096];
} AppConfig;

int config_init(AppConfig *config, int argc, char *argv[]);
void config_free(AppConfig *config);
void config_print_help(const char *program_name);
const char *config_last_error(void);
const char *config_scan_mode_label(const AppConfig *config);
const char *config_recover_mode_label(const AppConfig *config);
/* A category list containing the standalone token "all" is unrestricted,
 * regardless of any other category tokens around it. */
int config_category_csv_requests_all(const char *categories_csv);

/*
 * Folder scopes normally arrive as legacy comma-separated text.  The v1
 * form starts with "@scope-v1:" and percent-encodes each exact UTF-8 path,
 * so commas and other awkward filename bytes do not become separators.
 */
int config_scope_next_item(
    const char *scope_text,
    size_t *offset,
    char *out,
    size_t out_size
);
int config_scope_append_item_v1(
    char *out,
    size_t out_size,
    const char *item
);

#endif
