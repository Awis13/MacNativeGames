/* Save data shared through iCloud between the Mac and the iPad build (cloud_save.m). */
#pragma once

/* Before the game opens its save data: brings in the slots another device saved later than this one. */
void runtime_cloud_save_pull(const char *profile, const char *save_root);
/* After a commit of the save data: sends the changed slots (in the background). */
void runtime_cloud_save_push(void);
/* Before the process ends: waits up to timeout_ms for the sends in progress. */
void runtime_cloud_save_flush(int timeout_ms);
