#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void expect_item(const char *scope, size_t *offset, const char *expected)
{
    char item[512];

    assert(config_scope_next_item(scope, offset, item, sizeof(item)) == 1);
    assert(strcmp(item, expected) == 0);
}

int main(void)
{
    char encoded[1024] = "";
    size_t offset = 0U;
    AppConfig config;
    char *category_argv[] = {
        (char *)"carv",
        (char *)"--probe",
        (char *)"--cat",
        (char *)"images,documents,all"
    };

    assert(config_scope_append_item_v1(
        encoded,
        sizeof(encoded),
        "/Bilder/Bebis, BB/Åsa 😄.jpg"
    ));
    assert(config_category_csv_requests_all("all"));
    assert(config_category_csv_requests_all("images,documents,all"));
    assert(config_category_csv_requests_all(" images ; ALL ; video "));
    assert(!config_category_csv_requests_all("small"));
    assert(!config_category_csv_requests_all("images,documents"));
    assert(config_init(&config, 4, category_argv));
    assert(strcmp(config.mft_categories_csv, "all") == 0);
    assert(config.recover_img == 1);
    assert(config.recover_vid == 1);
    assert(config.recover_doc == 1);
    config_free(&config);
    assert(config_scope_append_item_v1(
        encoded,
        sizeof(encoded),
        "/mapp med blanksteg/back\\slash"
    ));
    assert(strncmp(encoded, "@scope-v1:", strlen("@scope-v1:")) == 0);

    expect_item(encoded, &offset, "/Bilder/Bebis, BB/Åsa 😄.jpg");
    expect_item(encoded, &offset, "/mapp med blanksteg/back\\slash");
    {
        char item[8];
        assert(config_scope_next_item(encoded, &offset, item, sizeof(item)) == 0);
    }

    offset = 0U;
    expect_item("Users, Pictures ,/", &offset, "Users");
    expect_item("Users, Pictures ,/", &offset, "Pictures");
    expect_item("Users, Pictures ,/", &offset, "/");

    offset = 0U;
    {
        char item[32];
        assert(config_scope_next_item("@scope-v1:/bad%GG", &offset, item, sizeof(item)) < 0);
    }

    puts("scope-list tests passed");
    return 0;
}
