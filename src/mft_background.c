#define _POSIX_C_SOURCE 200809L

#include "mft_background.h"
#include "log.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pid_t g_mft_background_pid = -1;
static int g_mft_background_write_fd = -1;
static volatile sig_atomic_t g_mft_background_stop_flag = 0;
static int g_mft_background_expected = 0;

static void mft_background_handle_stop_signal(int signal_number)
{
    (void)signal_number;
    g_mft_background_stop_flag = 1;
}

static int mft_background_refresh_child_state(int log_unexpected_exit)
{
    pid_t child_pid = g_mft_background_pid;
    int status = 0;
    int stop_requested = g_mft_background_stop_flag ? 1 : 0;
    pid_t wait_result;

    if (child_pid <= 0) {
        return 0;
    }

    wait_result = waitpid(child_pid, &status, WNOHANG);
    if (wait_result == 0) {
        return 1;
    }
    if (wait_result < 0 && errno == EINTR) {
        return 1;
    }

    if (g_mft_background_write_fd >= 0) {
        close(g_mft_background_write_fd);
        g_mft_background_write_fd = -1;
    }
    g_mft_background_pid = -1;

    if (!stop_requested && log_unexpected_exit) {
        if (wait_result == child_pid) {
            if (WIFSIGNALED(status)) {
                log_error(
                    "Spool-based MFT background helper exited unexpectedly with signal %d",
                    WTERMSIG(status)
                );
            } else if (WIFEXITED(status)) {
                log_error(
                    "Spool-based MFT background helper exited unexpectedly with status %d",
                    WEXITSTATUS(status)
                );
            } else {
                log_error("Spool-based MFT background helper exited unexpectedly");
            }
        } else if (wait_result < 0 && errno == ECHILD) {
            log_error(
                "Spool-based MFT background helper disappeared before it could be reaped; treating it as failed"
            );
        } else if (wait_result < 0) {
            log_error(
                "Failed to poll spool-based MFT background helper state: %s",
                strerror(errno)
            );
        }
    }

    if (stop_requested) {
        g_mft_background_stop_flag = 0;
    }

    return 0;
}

static void mft_background_child_loop(int control_fd)
{
    struct sigaction stop_action;

    g_mft_background_stop_flag = 0;
    memset(&stop_action, 0, sizeof(stop_action));
    stop_action.sa_handler = mft_background_handle_stop_signal;
    (void)sigaction(SIGINT, &stop_action, NULL);
    (void)sigaction(SIGTERM, &stop_action, NULL);
    (void)setpriority(PRIO_PROCESS, 0, 3);

    for (;;) {
        struct pollfd pfd;
        int poll_result;

        if (g_mft_background_stop_flag) {
            break;
        }

        pfd.fd = control_fd;
        pfd.events = POLLIN | POLLHUP | POLLERR;
        pfd.revents = 0;

        poll_result = poll(&pfd, 1, 100);
        if (poll_result < 0) {
            if (errno == EINTR) {
                if (g_mft_background_stop_flag) {
                    break;
                }
                continue;
            }
            break;
        }

        if (poll_result == 0) {
            if (g_mft_background_stop_flag) {
                break;
            }
            mft_engine_background_tick(0);
            continue;
        }

        if ((pfd.revents & (POLLHUP | POLLERR)) != 0) {
            break;
        }

        if ((pfd.revents & POLLIN) != 0) {
            char buffer[32];
            ssize_t bytes_read = read(control_fd, buffer, sizeof(buffer));

            if (bytes_read <= 0) {
                break;
            }
        }
    }

    mft_engine_close();
    close(control_fd);
    _exit(0);
}

int mft_background_start(const MftEngineConfig *config)
{
    int control_pipe[2];
    pid_t child_pid;

    (void)mft_background_refresh_child_state(0);
    if (g_mft_background_pid > 0) {
        return 1;
    }
    if (config == NULL) {
        return 0;
    }
    if (pipe(control_pipe) != 0) {
        log_error("Failed to create MFT background control pipe");
        return 0;
    }

    child_pid = fork();
    if (child_pid < 0) {
        close(control_pipe[0]);
        close(control_pipe[1]);
        log_error("Failed to fork MFT background helper");
        return 0;
    }

    if (child_pid == 0) {
        close(control_pipe[1]);
        mft_engine_prepare_background_child();
        mft_background_child_loop(control_pipe[0]);
    }

    close(control_pipe[0]);
    g_mft_background_expected = 1;
    g_mft_background_stop_flag = 0;
    g_mft_background_pid = child_pid;
    g_mft_background_write_fd = control_pipe[1];
    log_info("Spool-based MFT background helper started");
    return 1;
}

void mft_background_stop(void)
{
    pid_t child_pid;
    int status;
    int wait_tries = 0;

    g_mft_background_expected = 0;
    g_mft_background_stop_flag = 1;
    (void)mft_background_refresh_child_state(0);
    child_pid = g_mft_background_pid;

    if (g_mft_background_write_fd >= 0) {
        close(g_mft_background_write_fd);
        g_mft_background_write_fd = -1;
    }

    if (child_pid <= 0) {
        g_mft_background_pid = -1;
        return;
    }

    (void)kill(child_pid, SIGTERM);

    for (;;) {
        pid_t wait_result = waitpid(child_pid, &status, WNOHANG);

        if (wait_result == child_pid) {
            break;
        }
        if (wait_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (wait_tries++ >= 30) {
            (void)kill(child_pid, SIGKILL);
            while (waitpid(child_pid, &status, 0) < 0) {
                if (errno != EINTR) {
                    break;
                }
            }
            break;
        }

        {
            struct timespec delay;

            delay.tv_sec = 0;
            delay.tv_nsec = 50 * 1000 * 1000L;
            (void)nanosleep(&delay, NULL);
        }
    }

    g_mft_background_pid = -1;
    g_mft_background_stop_flag = 0;
    log_info("Spool-based MFT background helper stopped");
}

int mft_background_is_running(void)
{
    return mft_background_refresh_child_state(1);
}

int mft_background_expected_running(void)
{
    return g_mft_background_expected ? 1 : 0;
}

int mft_background_stop_requested(void)
{
    return g_mft_background_stop_flag ? 1 : 0;
}
