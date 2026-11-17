/* Input keyed to the game's own progress, not wall time (after Exhume's
 * runtime/replay, github.com/abedegno/exhume, MIT).
 *
 * A host counts frames however it already does (presents, flips, timer
 * ticks) and calls replay_log() for each input it delivers and replay_due()
 * once per frame for the inputs to deliver. Events are host-defined text;
 * by convention "key ...", "shot FILE" (a checkpoint: screenshot + hash) and
 * "end". The file is one event per line: "FRAME EVENT", '#' comments.
 *
 * replay_init(record, replay, keys): any may be NULL, then RECOMP_RECORD,
 * RECOMP_REPLAY and RECOMP_FKEYS are read. keys is the --keys form with
 * frame times: "f120:enter,f300:shot title.bmp". */
#ifndef PCRECOMP_REPLAY_H
#define PCRECOMP_REPLAY_H
#include <stddef.h>
#include <stdint.h>
int replay_init(const char *record, const char *replay, const char *keys); /* 1 if anything is queued */
void replay_log(uint32_t frame, const char *fmt, ...);
const char *replay_due(uint32_t frame);           /* next due event, or NULL; call until NULL */
const char *replay_path(const char *name);        /* name against the start-up directory */
uint32_t replay_hash(const void *p, size_t n);    /* FNV-1a, for checkpoint lines */
#endif
