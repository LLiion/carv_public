#ifndef MFT_BACKGROUND_H
#define MFT_BACKGROUND_H

#include "mft_engine.h"

int mft_background_start(const MftEngineConfig *config);
void mft_background_stop(void);
int mft_background_is_running(void);
int mft_background_expected_running(void);
int mft_background_stop_requested(void);

#endif
