/*
 * main.c
 * Program entry point for the file carver.
 * Keeps startup minimal and delegates execution to app_run().
 */

#include "app.h"

int main(int argc, char *argv[])
{
    return app_run(argc, argv);
}
