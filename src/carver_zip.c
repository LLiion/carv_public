#include "carver_zip.h"

#include "carver_output.h"
#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ZIP_LOCAL_FILE_HEADER_SIG 0x04034B50U
#define ZIP_CENTRAL_FILE_HEADER_SIG 0x02014B50U
#define ZIP_EOCD_SIG 0x06054B50U
#define ZIP64_EOCD_SIG 0x06064B50U
#define ZIP64_LOCATOR_SIG 0x07064B50U
#define ZIP_MIN_FILE_SIZE 64U

typedef struct {
    int valid_local_header;
    int valid_central_directory;
    int saw_content_types;
    int saw_root_rels;
    int saw_word;
    int saw_xl;
    int saw_ppt;
    int saw_mimetype_entry;
    int saw_meta_inf_manifest;
    int saw_epub_container;
    int saw_epub_opf;
    int saw_android_manifest;
    int saw_classes_dex;
    int saw_java_class;
    int saw_xps_fixed_doc_seq;
    int saw_xps_fixed_document;
    int saw_xps_fixed_page;
    int saw_any_name;
    size_t file_size;
    char extension[8];
    char mimetype[128];
} ZipAnalysis;

static CarverAuditReport g_zip_ooxml_last_audit;

void carver_zip_ooxml_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_zip_ooxml_last_audit);
}

void carver_zip_ooxml_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_zip_ooxml_last_audit;
}

static uint16_t read_u16_le_local(const uint8_t *data)
{
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static uint32_t read_u32_le_local(const uint8_t *data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static uint64_t read_u64_le_local(const uint8_t *data)
{
    return (uint64_t)read_u32_le_local(data) |
           ((uint64_t)read_u32_le_local(data + 4U) << 32);
}

static int zip_name_equals(
    const uint8_t *name,
    size_t name_length,
    const char *literal
)
{
    size_t literal_length;

    if (name == NULL || literal == NULL) {
        return 0;
    }

    literal_length = strlen(literal);
    return name_length == literal_length &&
           memcmp(name, literal, literal_length) == 0;
}

static int zip_name_has_prefix(
    const uint8_t *name,
    size_t name_length,
    const char *literal
)
{
    size_t literal_length;

    if (name == NULL || literal == NULL) {
        return 0;
    }

    literal_length = strlen(literal);
    return name_length >= literal_length &&
           memcmp(name, literal, literal_length) == 0;
}

static int zip_name_has_suffix(
    const uint8_t *name,
    size_t name_length,
    const char *literal
)
{
    size_t literal_length;

    if (name == NULL || literal == NULL) {
        return 0;
    }

    literal_length = strlen(literal);
    return name_length >= literal_length &&
           memcmp(name + name_length - literal_length, literal, literal_length) == 0;
}

static int zip_text_equals(const char *text, const char *literal)
{
    return text != NULL &&
           literal != NULL &&
           strcmp(text, literal) == 0;
}

static int write_zip_like_file(
    const uint8_t *buffer,
    size_t start_offset,
    size_t file_size,
    size_t absolute_offset,
    const char *extension
)
{
    return carver_output_write_buffer(
        (long long)absolute_offset,
        APP_DEFAULT_UNIDENT_DIR,
        "recov",
        extension,
        buffer + start_offset,
        file_size
    );
}

static void zip_read_stored_mimetype(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t file_size,
    uint64_t local_header_offset,
    uint16_t compression_method,
    uint64_t compressed_size,
    char *out,
    size_t out_size
)
{
    size_t local_offset;
    uint16_t local_name_length;
    uint16_t local_extra_length;
    size_t data_offset;
    size_t copy_length;
    size_t file_end;

    if (buffer == NULL ||
        out == NULL ||
        out_size == 0U ||
        compression_method != 0U ||
        compressed_size == 0U ||
        compressed_size >= out_size ||
        local_header_offset > (uint64_t)(SIZE_MAX - start_offset)) {
        return;
    }

    out[0] = '\0';
    local_offset = start_offset + (size_t)local_header_offset;
    file_end = start_offset + file_size;
    if (local_offset < start_offset ||
        local_offset + 30U > file_end ||
        local_offset + 30U > buffer_length ||
        read_u32_le_local(buffer + local_offset) != ZIP_LOCAL_FILE_HEADER_SIG) {
        return;
    }

    local_name_length = read_u16_le_local(buffer + local_offset + 26U);
    local_extra_length = read_u16_le_local(buffer + local_offset + 28U);
    data_offset = local_offset + 30U +
                  (size_t)local_name_length +
                  (size_t)local_extra_length;
    if (data_offset < local_offset ||
        (uint64_t)(file_end - data_offset) < compressed_size ||
        data_offset + (size_t)compressed_size > buffer_length) {
        return;
    }

    copy_length = (size_t)compressed_size;
    if (copy_length >= out_size) {
        copy_length = out_size - 1U;
    }
    memcpy(out, buffer + data_offset, copy_length);
    out[copy_length] = '\0';
}

static ZipAnalysis analyze_zip_candidate(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    uint32_t allowed_extensions
)
{
    ZipAnalysis result = {0};
    size_t eocd_offset = SIZE_MAX;
    size_t cursor;
    size_t file_size;
    uint16_t comment_length;
    uint64_t central_dir_offset;
    uint64_t central_dir_size;
    size_t central_dir_start;
    size_t central_dir_end;

    if (buffer == NULL || start_offset + ZIP_MIN_FILE_SIZE > buffer_length) {
        return result;
    }

    if (read_u32_le_local(buffer + start_offset) != ZIP_LOCAL_FILE_HEADER_SIG) {
        return result;
    }
    result.valid_local_header = 1;

    file_size = 0U;
    central_dir_offset = 0U;
    central_dir_size = 0U;
    central_dir_start = 0U;
    central_dir_end = 0U;
    for (cursor = start_offset + 22U;
         cursor + 22U <= buffer_length;
         cursor++) {
        size_t candidate_file_size;
        uint64_t candidate_central_dir_size;
        uint64_t candidate_central_dir_offset;
        size_t candidate_central_dir_start;
        size_t candidate_central_dir_end;

        if (read_u32_le_local(buffer + cursor) != ZIP_EOCD_SIG) {
            continue;
        }

        comment_length = read_u16_le_local(buffer + cursor + 20U);
        if (cursor > SIZE_MAX - 22U - (size_t)comment_length) {
            continue;
        }
        candidate_file_size = cursor + 22U + (size_t)comment_length - start_offset;
        if (candidate_file_size < ZIP_MIN_FILE_SIZE ||
            start_offset + candidate_file_size > buffer_length) {
            continue;
        }

        candidate_central_dir_size = (uint64_t)read_u32_le_local(buffer + cursor + 12U);
        candidate_central_dir_offset = (uint64_t)read_u32_le_local(buffer + cursor + 16U);

        if (candidate_central_dir_size == 0xFFFFFFFFULL ||
            candidate_central_dir_offset == 0xFFFFFFFFULL) {
            size_t locator_offset;

            if (cursor < 20U) {
                continue;
            }
            locator_offset = cursor - 20U;
            if (read_u32_le_local(buffer + locator_offset) != ZIP64_LOCATOR_SIG) {
                continue;
            }

            {
                uint64_t zip64_eocd_rel = read_u64_le_local(buffer + locator_offset + 8U);
                size_t zip64_eocd_offset;

                if (zip64_eocd_rel > (uint64_t)(SIZE_MAX - start_offset)) {
                    continue;
                }
                zip64_eocd_offset = start_offset + (size_t)zip64_eocd_rel;
                if (zip64_eocd_offset < start_offset ||
                    zip64_eocd_offset + 56U > start_offset + candidate_file_size ||
                    zip64_eocd_offset + 56U > buffer_length ||
                    read_u32_le_local(buffer + zip64_eocd_offset) != ZIP64_EOCD_SIG) {
                    continue;
                }

                candidate_central_dir_size =
                    read_u64_le_local(buffer + zip64_eocd_offset + 40U);
                candidate_central_dir_offset =
                    read_u64_le_local(buffer + zip64_eocd_offset + 48U);
            }
        }

        if (candidate_central_dir_size == 0U ||
            candidate_central_dir_size > (uint64_t)(SIZE_MAX - start_offset) ||
            candidate_central_dir_offset > (uint64_t)(SIZE_MAX - start_offset)) {
            continue;
        }
        candidate_central_dir_start = start_offset + (size_t)candidate_central_dir_offset;
        if (candidate_central_dir_start > SIZE_MAX - (size_t)candidate_central_dir_size) {
            continue;
        }
        candidate_central_dir_end =
            candidate_central_dir_start + (size_t)candidate_central_dir_size;
        if (candidate_central_dir_start < start_offset ||
            candidate_central_dir_end < candidate_central_dir_start ||
            candidate_central_dir_end > start_offset + candidate_file_size ||
            candidate_central_dir_start + 4U > buffer_length ||
            read_u32_le_local(buffer + candidate_central_dir_start) !=
                ZIP_CENTRAL_FILE_HEADER_SIG) {
            continue;
        }

        eocd_offset = cursor;
        file_size = candidate_file_size;
        central_dir_offset = candidate_central_dir_offset;
        central_dir_size = candidate_central_dir_size;
        central_dir_start = candidate_central_dir_start;
        central_dir_end = candidate_central_dir_end;
        break;
    }

    if (eocd_offset == SIZE_MAX ||
        central_dir_offset > (uint64_t)(SIZE_MAX - start_offset) ||
        central_dir_size > (uint64_t)(SIZE_MAX - start_offset)) {
        return result;
    }

    cursor = central_dir_start;
    while (cursor + 46U <= central_dir_end) {
        uint16_t file_name_length;
        uint16_t extra_length;
        uint16_t file_comment_length;
        uint16_t compression_method;
        uint64_t compressed_size;
        uint64_t local_header_offset;
        size_t record_size;
        const uint8_t *file_name;

        if (read_u32_le_local(buffer + cursor) != ZIP_CENTRAL_FILE_HEADER_SIG) {
            return result;
        }

        file_name_length = read_u16_le_local(buffer + cursor + 28U);
        extra_length = read_u16_le_local(buffer + cursor + 30U);
        file_comment_length = read_u16_le_local(buffer + cursor + 32U);
        compression_method = read_u16_le_local(buffer + cursor + 10U);
        compressed_size = (uint64_t)read_u32_le_local(buffer + cursor + 20U);
        local_header_offset = (uint64_t)read_u32_le_local(buffer + cursor + 42U);
        record_size = 46U +
                      (size_t)file_name_length +
                      (size_t)extra_length +
                      (size_t)file_comment_length;

        if (record_size > central_dir_end - cursor) {
            return result;
        }

        file_name = buffer + cursor + 46U;
        if (file_name_length > 0) {
            result.saw_any_name = 1;
        }
        if (zip_name_equals(file_name, file_name_length, "[Content_Types].xml")) {
            result.saw_content_types = 1;
        } else if (zip_name_equals(file_name, file_name_length, "_rels/.rels")) {
            result.saw_root_rels = 1;
        } else if (zip_name_has_prefix(file_name, file_name_length, "word/")) {
            result.saw_word = 1;
        } else if (zip_name_has_prefix(file_name, file_name_length, "xl/")) {
            result.saw_xl = 1;
        } else if (zip_name_has_prefix(file_name, file_name_length, "ppt/")) {
            result.saw_ppt = 1;
        } else if (zip_name_equals(file_name, file_name_length, "mimetype")) {
            result.saw_mimetype_entry = 1;
            zip_read_stored_mimetype(
                buffer,
                buffer_length,
                start_offset,
                file_size,
                local_header_offset,
                compression_method,
                compressed_size,
                result.mimetype,
                sizeof(result.mimetype));
        } else if (zip_name_equals(file_name, file_name_length, "META-INF/manifest.xml")) {
            result.saw_meta_inf_manifest = 1;
        } else if (zip_name_equals(file_name, file_name_length, "META-INF/container.xml")) {
            result.saw_epub_container = 1;
        } else if (zip_name_has_suffix(file_name, file_name_length, ".opf")) {
            result.saw_epub_opf = 1;
        } else if (zip_name_equals(file_name, file_name_length, "AndroidManifest.xml")) {
            result.saw_android_manifest = 1;
        } else if (zip_name_equals(file_name, file_name_length, "classes.dex")) {
            result.saw_classes_dex = 1;
        } else if (zip_name_has_suffix(file_name, file_name_length, ".class")) {
            result.saw_java_class = 1;
        } else if (zip_name_has_suffix(file_name, file_name_length, ".fdseq")) {
            result.saw_xps_fixed_doc_seq = 1;
        } else if (zip_name_has_suffix(file_name, file_name_length, ".fdoc")) {
            result.saw_xps_fixed_document = 1;
        } else if (zip_name_has_suffix(file_name, file_name_length, ".fpage")) {
            result.saw_xps_fixed_page = 1;
        }

        cursor += record_size;
    }

    if (cursor != central_dir_end || !result.saw_any_name) {
        return result;
    }

    result.valid_central_directory = 1;
    result.file_size = file_size;

    if (zip_text_equals(result.mimetype, "application/vnd.oasis.opendocument.text")) {
        snprintf(result.extension, sizeof(result.extension), "odt");
    } else if (zip_text_equals(
                   result.mimetype,
                   "application/vnd.oasis.opendocument.spreadsheet")) {
        snprintf(result.extension, sizeof(result.extension), "ods");
    } else if (zip_text_equals(
                   result.mimetype,
                   "application/vnd.oasis.opendocument.presentation")) {
        snprintf(result.extension, sizeof(result.extension), "odp");
    } else if (zip_text_equals(result.mimetype, "application/epub+zip") ||
               (result.saw_epub_container && result.saw_epub_opf)) {
        snprintf(result.extension, sizeof(result.extension), "epub");
    } else if (result.saw_android_manifest && result.saw_classes_dex) {
        snprintf(result.extension, sizeof(result.extension), "apk");
    } else if (result.saw_content_types &&
               (result.saw_xps_fixed_doc_seq ||
                result.saw_xps_fixed_document ||
                result.saw_xps_fixed_page)) {
        snprintf(result.extension, sizeof(result.extension), "xps");
    } else if (result.saw_content_types &&
               (result.saw_word || result.saw_xl || result.saw_ppt)) {
        if (result.saw_word && !result.saw_xl && !result.saw_ppt) {
            snprintf(result.extension, sizeof(result.extension), "docx");
        } else if (result.saw_xl && !result.saw_word && !result.saw_ppt) {
            snprintf(result.extension, sizeof(result.extension), "xlsx");
        } else if (result.saw_ppt && !result.saw_word && !result.saw_xl) {
            snprintf(result.extension, sizeof(result.extension), "pptx");
        } else if ((allowed_extensions & CARVER_ZIP_ALLOW_ZIP) != 0U) {
            snprintf(result.extension, sizeof(result.extension), "zip");
        }
    } else if (result.saw_meta_inf_manifest || result.saw_java_class) {
        snprintf(result.extension, sizeof(result.extension), "jar");
    } else if ((allowed_extensions & CARVER_ZIP_ALLOW_ZIP) != 0U) {
        snprintf(result.extension, sizeof(result.extension), "zip");
    }

    return result;
}

static int zip_extension_allowed(const char *extension, uint32_t allowed_extensions)
{
    if (extension == NULL) {
        return 0;
    }
    if (strcmp(extension, "docx") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_DOCX) != 0U;
    }
    if (strcmp(extension, "xlsx") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_XLSX) != 0U;
    }
    if (strcmp(extension, "pptx") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_PPTX) != 0U;
    }
    if (strcmp(extension, "zip") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_ZIP) != 0U;
    }
    if (strcmp(extension, "odt") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_ODT) != 0U;
    }
    if (strcmp(extension, "ods") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_ODS) != 0U;
    }
    if (strcmp(extension, "odp") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_ODP) != 0U;
    }
    if (strcmp(extension, "epub") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_EPUB) != 0U;
    }
    if (strcmp(extension, "apk") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_APK) != 0U;
    }
    if (strcmp(extension, "jar") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_JAR) != 0U;
    }
    if (strcmp(extension, "xps") == 0) {
        return (allowed_extensions & CARVER_ZIP_ALLOW_XPS) != 0U;
    }
    return 0;
}

int carver_zip_family_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    uint32_t allowed_extensions,
    size_t *confirmed_span_out
)
{
    ZipAnalysis analysis;

    carver_zip_ooxml_reset_last_audit();
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0;
    }
    if (buffer == NULL || start_offset >= buffer_length) {
        carver_audit_set_inline(&g_zip_ooxml_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }

    analysis = analyze_zip_candidate(
        buffer,
        buffer_length,
        start_offset,
        allowed_extensions
    );

    if (!analysis.valid_local_header ||
        !analysis.valid_central_directory ||
        analysis.file_size < ZIP_MIN_FILE_SIZE ||
        analysis.extension[0] == '\0') {
        carver_audit_set_inline(&g_zip_ooxml_last_audit, "rejected", "invalid_zip_structure", 0U);
        return 0;
    }

    if (!zip_extension_allowed(analysis.extension, allowed_extensions)) {
        carver_audit_set_inline(&g_zip_ooxml_last_audit, "skipped", "disabled_by_format_filter", 0U);
        return 0;
    }

    if (!write_zip_like_file(
            buffer,
            start_offset,
            analysis.file_size,
            absolute_offset,
            analysis.extension)) {
        carver_audit_set_inline(
            &g_zip_ooxml_last_audit,
            "rejected",
            "write_failed",
            analysis.file_size);
        return 0;
    }

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = analysis.file_size;
    }
    carver_audit_set_inline(
        &g_zip_ooxml_last_audit,
        "recovered",
        "accepted",
        analysis.file_size);
    return 1;
}
