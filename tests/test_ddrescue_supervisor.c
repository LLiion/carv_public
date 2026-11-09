#include "ddrescue_supervisor.h"

#include <assert.h>
#include <stdio.h>

static void test_slow_kernel_read_warns_but_does_not_claim_a_crash(void)
{
    DdrescueSupervisor supervisor;

    ddrescue_supervisor_init(&supervisor, 100.0);
    assert(ddrescue_supervisor_observe(
               &supervisor, 'D', 0, 100.0) ==
           DDRESCUE_SUPERVISOR_ACTIVE);
    assert(ddrescue_supervisor_observe(
               &supervisor, 'D', 0, 161.0) ==
           DDRESCUE_SUPERVISOR_SUSPECTED_STALL);
    assert(!ddrescue_supervisor_kernel_fault_confirmed(&supervisor));
    assert(ddrescue_supervisor_observe(
               &supervisor, 'D', 1, 162.0) ==
           DDRESCUE_SUPERVISOR_ACTIVE);
    assert(ddrescue_supervisor_observe(
               &supervisor, 'S', 0, 163.0) ==
           DDRESCUE_SUPERVISOR_ACTIVE);
    ddrescue_supervisor_close(&supervisor);
}

static void test_unrelated_kernel_fault_does_not_stop_ddrescue(void)
{
    DdrescueSupervisor supervisor;

    ddrescue_supervisor_init(&supervisor, 200.0);
    ddrescue_supervisor_note_kernel_message(
        &supervisor,
        "BUG: unable to handle page fault in an unrelated graphics worker",
        201.0
    );
    assert(ddrescue_supervisor_observe(
               &supervisor, 'D', 0, 201.0) ==
           DDRESCUE_SUPERVISOR_ACTIVE);
    assert(ddrescue_supervisor_observe(
               &supervisor, 'D', 0, 212.0) ==
           DDRESCUE_SUPERVISOR_ACTIVE);
    assert(!ddrescue_supervisor_kernel_fault_confirmed(&supervisor));
    ddrescue_supervisor_close(&supervisor);
}

static void test_storage_kernel_fault_and_blocked_child_require_reboot(void)
{
    DdrescueSupervisor supervisor;

    ddrescue_supervisor_init(&supervisor, 300.0);
    ddrescue_supervisor_note_kernel_message(
        &supervisor,
        "BUG: unable to handle page fault for address 0000000048ea8987",
        301.0
    );
    ddrescue_supervisor_note_kernel_message(
        &supervisor,
        "RIP: iommu_dma_map_sg+0x318/0x630",
        302.0
    );
    assert(ddrescue_supervisor_kernel_fault_confirmed(&supervisor));
    assert(ddrescue_supervisor_observe(
               &supervisor, 'D', 0, 302.0) ==
           DDRESCUE_SUPERVISOR_ACTIVE);
    assert(ddrescue_supervisor_observe(
               &supervisor, 'D', 0, 313.0) ==
           DDRESCUE_SUPERVISOR_KERNEL_IO_HANG);
    assert(ddrescue_supervisor_blocked_seconds(&supervisor, 313.0) == 11.0);
    assert(ddrescue_supervisor_no_progress_seconds(&supervisor, 313.0) == 13.0);
    ddrescue_supervisor_close(&supervisor);
}

static void test_fault_and_storage_lines_must_belong_to_same_event(void)
{
    DdrescueSupervisor supervisor;

    ddrescue_supervisor_init(&supervisor, 400.0);
    ddrescue_supervisor_note_kernel_message(
        &supervisor,
        "BUG: unable to handle page fault",
        401.0
    );
    ddrescue_supervisor_note_kernel_message(
        &supervisor,
        "usb_stor_Bulk_transport",
        440.0
    );
    assert(!ddrescue_supervisor_kernel_fault_confirmed(&supervisor));
    ddrescue_supervisor_close(&supervisor);
}

int main(void)
{
    test_slow_kernel_read_warns_but_does_not_claim_a_crash();
    test_unrelated_kernel_fault_does_not_stop_ddrescue();
    test_storage_kernel_fault_and_blocked_child_require_reboot();
    test_fault_and_storage_lines_must_belong_to_same_event();
    puts("ddrescue kernel-I/O supervisor checks passed");
    return 0;
}
