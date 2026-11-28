/* The host's sound mixer (audio.c, after Theme Park's). Voices play PCM from guest memory. */
#pragma once
#include <stdint.h>

/* silent: no device (headless); audio_render then mixes on demand. */
int  audio_init(int silent);
int  audio_rate(void);
int  audio_live(void);   /* a device is open */
void audio_render(int16_t* stereo, int frames);

/* Returns a voice id (0 = not played). vol 0..127, pan 0..127 (64 centre); ch 1 or 2
 * (interleaved; a stereo voice ignores pan); loop is how many times to repeat after the
 * first play, -1 for ever. */
int  audio_play_ch(const void* data, uint32_t bytes, int bits, int is_signed, int ch, int rate,
                   int vol, int pan, int loop);
/* What the voice plays when it reaches its end (a stream's next buffer): 0 when one is
 * queued already or the voice has ended. */
int  audio_queue(int id, const void* data, uint32_t bytes);
int  audio_queued(int id);                             /* a next buffer waits */
void audio_stop(int id);
int  audio_playing(int id);
void audio_set(int id, int vol, int pan, int rate);   /* -1 leaves a field */
void audio_loop(int id, int loop);
void audio_pause(int id, int paused);
void audio_stop_all(void);
void audio_master(int vol);
