#include "container_context.h"

#include <stddef.h>
#include <string.h>

static char ascii_tolower_local(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char)(c - 'A' + 'a');
    }

    return c;
}

static int path_has_segment_ci(const char *path, const char *segment_name)
{
    const char *cursor;

    if (path == NULL || segment_name == NULL) {
        return 0;
    }

    cursor = path;
    while (*cursor == '/' || *cursor == '\\') {
        cursor++;
    }

    while (*cursor != '\0') {
        const char *next_slash = cursor;
        size_t segment_len = (next_slash == NULL)
            ? strlen(cursor)
            : 0U;
        size_t name_len = strlen(segment_name);
        size_t i;
        int match = 1;

        while (*next_slash != '\0' && *next_slash != '/' && *next_slash != '\\') {
            next_slash++;
        }
        segment_len = (size_t)(next_slash - cursor);

        if (segment_len == name_len) {
            for (i = 0; i < name_len; i++) {
                if (ascii_tolower_local(cursor[i]) !=
                    ascii_tolower_local(segment_name[i])) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                return 1;
            }
        }

        if (next_slash == NULL) {
            break;
        }

        cursor = next_slash + 1;
        while (*cursor == '/' || *cursor == '\\') {
            cursor++;
        }
    }

    return 0;
}

ContainerContextKind container_context_kind_from_path(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return CONTAINER_CONTEXT_UNKNOWN;
    }

    if (path_has_segment_ci(path, ".thumbs") ||
        path_has_segment_ci(path, ".thumbnails") ||
        path_has_segment_ci(path, "thumbs") ||
        path_has_segment_ci(path, "thumbnails") ||
        path_has_segment_ci(path, "thumbcache") ||
        path_has_segment_ci(path, "thumbnailcache")) {
        return CONTAINER_CONTEXT_THUMBNAIL_CACHE;
    }

    if (path_has_segment_ci(path, "Spotify") &&
        path_has_segment_ci(path, "Browser") &&
        path_has_segment_ci(path, "Cache_Data")) {
        return CONTAINER_CONTEXT_SPOTIFY_BROWSER_CACHE;
    }

    if (path_has_segment_ci(path, "Google") &&
        path_has_segment_ci(path, "Chrome") &&
        path_has_segment_ci(path, "Cache_Data")) {
        return CONTAINER_CONTEXT_CHROME_CACHE;
    }

    if (path_has_segment_ci(path, "Microsoft") &&
        path_has_segment_ci(path, "Edge") &&
        path_has_segment_ci(path, "Cache_Data")) {
        return CONTAINER_CONTEXT_EDGE_CACHE;
    }

    if (path_has_segment_ci(path, "AVAST Software") &&
        path_has_segment_ci(path, "Browser") &&
        path_has_segment_ci(path, "Cache_Data")) {
        return CONTAINER_CONTEXT_AVAST_BROWSER_CACHE;
    }

    if (path_has_segment_ci(path, "File System") &&
        ((path_has_segment_ci(path, "Chrome") && path_has_segment_ci(path, "User Data")) ||
         (path_has_segment_ci(path, "Edge") && path_has_segment_ci(path, "User Data")))) {
        return CONTAINER_CONTEXT_BROWSER_FILE_SYSTEM;
    }

    if (path_has_segment_ci(path, "Comms") &&
        path_has_segment_ci(path, "Unistore")) {
        return CONTAINER_CONTEXT_WINDOWS_UNISTORE;
    }

    if (path_has_segment_ci(path, "WinSxS") &&
        path_has_segment_ci(path, "Temp") &&
        path_has_segment_ci(path, "InFlight")) {
        return CONTAINER_CONTEXT_WINSXS_TEMP_INFLIGHT;
    }

    if (path_has_segment_ci(path, "Packages") &&
        (path_has_segment_ci(path, "LocalState") ||
         path_has_segment_ci(path, "AppState.json") ||
         path_has_segment_ci(path, "LocalCache"))) {
        return CONTAINER_CONTEXT_APP_PACKAGE_STATE;
    }

    if (path_has_segment_ci(path, "Cache_Data")) {
        return CONTAINER_CONTEXT_GENERIC_CACHE_DATA;
    }

    return CONTAINER_CONTEXT_UNKNOWN;
}

const char *container_context_label(ContainerContextKind kind)
{
    switch (kind) {
        case CONTAINER_CONTEXT_THUMBNAIL_CACHE:
            return "thumbnail_cache";
        case CONTAINER_CONTEXT_CHROME_CACHE:
            return "chrome_cache";
        case CONTAINER_CONTEXT_EDGE_CACHE:
            return "edge_cache";
        case CONTAINER_CONTEXT_AVAST_BROWSER_CACHE:
            return "avast_browser_cache";
        case CONTAINER_CONTEXT_SPOTIFY_BROWSER_CACHE:
            return "spotify_browser_cache";
        case CONTAINER_CONTEXT_BROWSER_FILE_SYSTEM:
            return "browser_file_system";
        case CONTAINER_CONTEXT_WINDOWS_UNISTORE:
            return "windows_unistore";
        case CONTAINER_CONTEXT_APP_PACKAGE_STATE:
            return "app_package_state";
        case CONTAINER_CONTEXT_WINSXS_TEMP_INFLIGHT:
            return "winsxs_temp_inflight";
        case CONTAINER_CONTEXT_GENERIC_CACHE_DATA:
            return "generic_cache_data";
        case CONTAINER_CONTEXT_UNKNOWN:
        default:
            return "unknown";
    }
}

const char *container_context_label_from_path(const char *path)
{
    return container_context_label(container_context_kind_from_path(path));
}
