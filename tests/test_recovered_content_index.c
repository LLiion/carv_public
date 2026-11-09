#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include "recovered_content_index.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr,"check failed line %d: %s (errno=%d)\n",__LINE__,#condition,errno); \
    goto cleanup; } } while (0)

static int write_bytes(const char *path, const char *bytes)
{
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    size_t size = strlen(bytes);
    int ok = fd >= 0 && write(fd, bytes, size) == (ssize_t)size && fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0) ok = 0;
    return ok;
}

static int file_contains(const char *path, const char *needle)
{
    char buffer[8192];
    FILE *file = fopen(path,"r");
    size_t got;
    if (file == NULL) return 0;
    got = fread(buffer,1,sizeof(buffer)-1U,file);
    fclose(file); buffer[got]='\0';
    return strstr(buffer,needle)!=NULL;
}

static int simulate_remount_identity_change(const char *database_path)
{
    sqlite3 *db = NULL;
    int ok = sqlite3_open(database_path, &db) == SQLITE_OK &&
        sqlite3_exec(db,
            "UPDATE files SET dev=dev+1000,inode=inode+1000000",
            NULL, NULL, NULL) == SQLITE_OK;
    if (db != NULL) sqlite3_close(db);
    return ok;
}

int main(void)
{
    char root[]="/tmp/carv-content-index-XXXXXX";
    char recovered[512], named[512], unident[512], state[512];
    char a[512], b[512], c[512], moved[512], unique[512], noise[512];
    char plan[512], status[512], ledger[512], catalog_duplicates[512], database[512];
    char ledger_text[1200];
    RecoveredContentIndexOptions budget_options={0};
    RecoveredContentIndexOptions slice_options={0};
    RecoveredContentIndexStats budgeted={0}, preserved={0}, first={0}, second={0}, changed={0}, renamed={0};
    uint64_t previous_slice_files=0U;
    unsigned slice_iterations=0U;
    int saw_resumed_slice=0;
    int saw_forward_progress=0;
    int result=1;

    CHECK(mkdtemp(root)!=NULL);
    CHECK(snprintf(recovered,sizeof(recovered),"%s/recovered",root)<(int)sizeof(recovered));
    CHECK(snprintf(named,sizeof(named),"%s/Named",recovered)<(int)sizeof(named));
    CHECK(snprintf(unident,sizeof(unident),"%s/Unidentified/jpg",recovered)<(int)sizeof(unident));
    CHECK(snprintf(state,sizeof(state),"%s/state",root)<(int)sizeof(state));
    CHECK(mkdir(recovered,0700)==0 && mkdir(named,0700)==0 && mkdir(state,0700)==0);
    CHECK(mkdir(strcat(strcpy(a,recovered),"/Unidentified"),0700)==0);
    CHECK(mkdir(unident,0700)==0);
    CHECK(snprintf(a,sizeof(a),"%s/customer.jpg",named)<(int)sizeof(a));
    CHECK(snprintf(b,sizeof(b),"%s/recov_123.jpg",unident)<(int)sizeof(b));
    CHECK(snprintf(c,sizeof(c),"%s/recov_456.jpg",unident)<(int)sizeof(c));
    CHECK(snprintf(moved,sizeof(moved),"%s/relocated.jpg",named)<(int)sizeof(moved));
    CHECK(snprintf(unique,sizeof(unique),"%s/unique.bin",named)<(int)sizeof(unique));
    CHECK(snprintf(noise,sizeof(noise),"%s/._customer.jpg",recovered)<(int)sizeof(noise));
    CHECK(snprintf(plan,sizeof(plan),"%s/duplicate_plan.tsv",state)<(int)sizeof(plan));
    CHECK(snprintf(status,sizeof(status),"%s/duplicate_status.txt",state)<(int)sizeof(status));
    CHECK(snprintf(ledger,sizeof(ledger),"%s/recovered_outputs.tsv",state)<(int)sizeof(ledger));
    CHECK(snprintf(catalog_duplicates,sizeof(catalog_duplicates),
                   "%s/exact_catalog_duplicates.tsv",state)<(int)sizeof(catalog_duplicates));
    CHECK(snprintf(database,sizeof(database),"%s/content_index.sqlite3",state)<(int)sizeof(database));
    CHECK(snprintf(ledger_text,sizeof(ledger_text),
                   "offset\tpath\treconciled\n77\t%s\t1\n",a)<(int)sizeof(ledger_text));
    CHECK(write_bytes(a,"abc") && write_bytes(b,"abc") &&
          write_bytes(c,"xyz") && write_bytes(unique,"unique") &&
          write_bytes(noise,"client-side metadata") && write_bytes(ledger,ledger_text));

    budget_options.time_budget_seconds=0.000001;
    CHECK(recovered_content_index_update(root,&budget_options,&budgeted));
    CHECK(!budgeted.completed && budgeted.budget_exhausted);
    CHECK(budgeted.files_seen==0U);
    CHECK(file_contains(status,"status=checkpoint"));
    CHECK(file_contains(status,"checkpoint_phase="));

    CHECK(recovered_content_index_update(root,NULL,&first));
    CHECK(first.files_seen==4U && first.candidate_files==3U);
    CHECK(first.files_bytes==15U && file_contains(status,"files_bytes=15"));
    CHECK(first.client_artifacts_ignored==1U);
    CHECK(first.files_hashed_now==3U && first.duplicate_groups==1U);
    CHECK(first.redundant_copies==1U && first.redundant_bytes==3U);
    CHECK(first.catalog_duplicate_groups==1U && first.catalog_duplicate_files==1U);
    CHECK(first.catalog_duplicate_bytes==3U);
    CHECK(file_contains(plan,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK(file_contains(plan,"\t1\t77\tnamed_or_contextual\t"));
    CHECK(file_contains(plan,"\t123\tunidentified\t"));
    CHECK(file_contains(catalog_duplicates,"distinct_physical_occurrence"));
    CHECK(file_contains(catalog_duplicates,"exact_duplicate_of_named_catalog_file"));
    CHECK(file_contains(catalog_duplicates,a) && file_contains(catalog_duplicates,b));

    /* Every bounded refresh resumes its durable ledger/tree queue.  With a
     * two-item deterministic slice this can only finish by continuing from
     * earlier slices instead of walking from the root each time. */
    slice_options.work_item_budget=2U;
    for (slice_iterations=0U; slice_iterations<64U; ++slice_iterations) {
        memset(&preserved,0,sizeof(preserved));
        CHECK(recovered_content_index_update(root,&slice_options,&preserved));
        CHECK(preserved.files_seen>=previous_slice_files);
        if (preserved.files_seen>previous_slice_files) saw_forward_progress=1;
        previous_slice_files=preserved.files_seen;
        if (preserved.completed) break;
        CHECK(preserved.budget_exhausted);
        CHECK(preserved.generation==first.generation+1U);
        CHECK(file_contains(status,"snapshot_preserved=1"));
        CHECK(file_contains(plan,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        if (preserved.checkpoint_resumed) saw_resumed_slice=1;
    }
    CHECK(preserved.completed && slice_iterations<64U);
    CHECK(saw_resumed_slice && saw_forward_progress);

    CHECK(simulate_remount_identity_change(database));
    CHECK(recovered_content_index_update(root,NULL,&second));
    CHECK(second.files_hashed_now==0U && second.hashes_reused==3U);
    CHECK(second.duplicate_groups==1U && second.redundant_copies==1U);

    CHECK(write_bytes(a,"xyz"));
    CHECK(recovered_content_index_update(root,NULL,&changed));
    CHECK(changed.files_hashed_now==1U && changed.hashes_reused==2U);
    CHECK(changed.duplicate_groups==1U && changed.redundant_copies==1U);
    CHECK(rename(c,moved)==0);
    CHECK(recovered_content_index_update(root,NULL,&renamed));
    CHECK(renamed.files_hashed_now==0U && renamed.hashes_reused==3U);
    CHECK(renamed.duplicate_groups==1U && renamed.redundant_copies==1U);
    result=0;
cleanup:
    if (root[0]!='\0') {
        unlink(a); unlink(b); unlink(c); unlink(moved); unlink(unique); unlink(noise);
        unlink(plan); unlink(status); unlink(ledger); unlink(catalog_duplicates);
        snprintf(a,sizeof(a),"%s/content_index.sqlite3",state); unlink(a);
        rmdir(unident); snprintf(a,sizeof(a),"%s/Unidentified",recovered); rmdir(a);
        rmdir(named); rmdir(recovered); rmdir(state); rmdir(root);
    }
    if (result==0) printf("recovered-content-index checks passed\n");
    return result;
}
