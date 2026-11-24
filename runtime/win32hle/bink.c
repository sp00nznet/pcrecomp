/*
 * bink.c - BINKW32 (RAD's Bink movie player, the 1.x API) on ffmpeg's Bink
 * decoder.
 *
 * A game links binkw32.dll and calls it by its decorated names
 * (_BinkOpen@8, ...); the DLL's code is not lifted, so its API is answered
 * here: libavformat reads the .bik (a file name, or with BINKFILEHANDLE a
 * file handle the game positioned itself, at a movie inside an archive),
 * libavcodec decodes its video and audio, BinkCopyToBuffer converts a frame
 * into the game's surface, and the sound goes to the DirectSound mixer as a
 * stream (dsound.c), started with the movie and paced by its frame rate.
 *
 * The handle the game gets is a BINK struct whose leading fields are
 * Bink's own (Width, Height, Frames, FrameNum, LastFrameNum, FrameRate,
 * FrameRateDiv, ...): games read them directly. Without HLE_WITH_FFMPEG,
 * BinkOpen fails, as with a movie that is not there.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "win32hle.h"

#define BINKFILEHANDLE 0x00800000u

static const char *g_error = "";
static void k_GetError(void) {                           /* a copy in guest memory, made once per message */
    static const char *copied_from;
    static uint32_t va;
    if (copied_from != g_error) va = hle_guest_strdup(g_error), copied_from = g_error;
    RET(va, 0);
}
static void k_SetSoundSystem(void) { RET(1, 2); }        /* (open, param): DirectSound, which is ours */
static void k_OpenDirectSound(void) { RET(0, 1); }
/* BinkDDSurfaceType(surface): the BINKSURFACE type of a DirectDraw surface */
static void k_DDSurfaceType(void) {
    uint8_t *px;
    int w, h, pitch, bpp;
    if (!hle_dd_surface_pixels(A32(0), &px, &w, &h, &pitch, &bpp)) RET(0xFFFFFFFFu, 1);
    RET(bpp == 16 ? 10u /* 565 */ : bpp == 32 ? 3u /* 32 */ : bpp == 24 ? 1u : 0u, 1);
}

#ifdef __EMSCRIPTEN__
/* In a browser the page plays the movie (web/movies.js: transcoded once by
 * ffmpeg.wasm, then a <video>), and copies each frame, as RGBA, into a
 * buffer here, with a state block the page writes: ready (1; 2 failed),
 * the newest frame's number, ended, the preparation's progress (per mille),
 * then the size and the buffer. BinkOpen hands the page the movie's bytes
 * and waits for it to be ready; the frame calls read the block. The sound
 * is the video's own, not the mixer's. */
#include <emscripten.h>
typedef struct { volatile uint32_t ready, frame, ended, progress, w, h; uint32_t rgba; } web_movie_t;
typedef struct {
    uint32_t Width, Height, Frames, FrameNum, LastFrameNum, FrameRate, FrameRateDiv, ReadError, OpenFlags, BinkType,
             Size, FrameSize, SndSize;
    uint32_t pad[64];
    web_movie_t *st;
    int id;
    uint32_t shown;                                        /* the frame BinkDoFrame last took */
    int paused;
    int wrapped;                                           /* past the last frame: FrameNum went back to 1 */
} bink_t;
static int g_movie_ids;
static void web_movie_ctl(int id, int what, int value) {
    MAIN_THREAD_ASYNC_EM_ASM({ if (Module['ra2MovieCtl']) Module['ra2MovieCtl']($0, $1, $2); }, id, what, value);
}
static void k_Open(void) {                               /* (name or handle, flags) */
    uint32_t flags = A32(1);
    uint8_t hdr[44];
    int fd, own = 0;
    off_t base = 0;
    if (flags & BINKFILEHANDLE) { fd = hle_file_fd(A32(0)); if (fd >= 0) base = lseek(fd, 0, SEEK_CUR); }
    else {
        char path[1024];
        hle_host_path(ASTR(0), path, sizeof path);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        own = 1;
    }
    if (fd < 0) { g_error = "cannot open the movie"; RET(0, 2); }
    if (pread(fd, hdr, sizeof hdr, base) < (ssize_t)sizeof hdr || memcmp(hdr, "BIK", 3) != 0) {
        if (own) close(fd);
        g_error = "not a Bink movie";
        RET(0, 2);
    }
    bink_t *b = (bink_t *)hle_alloc(sizeof *b);
    memcpy(&b->Size, hdr + 4, 4);
    memcpy(&b->Frames, hdr + 8, 4);
    memcpy(&b->FrameSize, hdr + 12, 4);
    memcpy(&b->Width, hdr + 20, 4);
    memcpy(&b->Height, hdr + 24, 4);
    memcpy(&b->FrameRate, hdr + 28, 4);
    memcpy(&b->FrameRateDiv, hdr + 32, 4);
    if (!b->FrameRate) b->FrameRate = 15;
    if (!b->FrameRateDiv) b->FrameRateDiv = 1;
    b->FrameNum = 1, b->OpenFlags = flags, b->id = ++g_movie_ids;
    /* the whole movie, for the page */
    size_t len = (size_t)b->Size + 8;
    uint8_t *buf = len < (256u << 20) ? (uint8_t *)malloc(len) : NULL;
    size_t got = 0;
    while (buf && got < len) {
        ssize_t r = pread(fd, buf + got, len - got, base + (off_t)got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    if (own) close(fd);
    if (buf && got == len && b->Width && b->Height) {
        web_movie_t *st = (web_movie_t *)calloc(1, sizeof *st);
        st->w = b->Width, st->h = b->Height;
        st->rgba = (uint32_t)(uintptr_t)calloc((size_t)b->Width * b->Height, 4);
        b->st = st;
        MAIN_THREAD_EM_ASM({ if (Module['ra2MovieOpen']) Module['ra2MovieOpen']($0, $1, $2, $3, $4, $5, $6, $7); else HEAPU32[$3 >> 2] = 2; },
                           b->id, buf, (int)len, st, (int)b->Width, (int)b->Height, (double)b->FrameRate / b->FrameRateDiv, (int)b->Frames);
        free(buf);
        uint32_t t0 = hle_ticks_ms(), said = 0;
        while (st->ready == 0 && hle_ticks_ms() - t0 < 30u * 60u * 1000u) {
            hle_block_begin(); usleep(50000); hle_block_end();
            if (hle_ticks_ms() - t0 > said + 3000) { said = hle_ticks_ms() - t0; fprintf(stderr, "[bink] preparing the movie: %u%%\n", st->progress / 10); }
        }
        if (st->ready != 1) {
            fprintf(stderr, "[bink] the page could not play the movie: skipped\n");
            free((void *)(uintptr_t)st->rgba);
            free(st);
            b->st = NULL;
        }
    } else {
        free(buf);
        fprintf(stderr, "[bink] cannot read the movie (%u bytes): skipped\n", (unsigned)len);
    }
    RET(hle_va(b), 2);
}
static void k_Close(void) {
    bink_t *b = (bink_t *)APTR(0);
    if (!b) RETV(1);
    if (b->st) { web_movie_ctl(b->id, 4, 0); free((void *)(uintptr_t)b->st->rgba); free(b->st); }
    hle_free(b);
    RETV(1);
}
static void k_DoFrame(void) {
    bink_t *b = (bink_t *)APTR(0);
    if (b) { if (b->st) b->shown = b->st->frame; b->LastFrameNum = b->FrameNum; }
    RET(0, 1);
}
/* As Bink does: past the last frame, FrameNum goes back to 1, and BinkWait
 * then waits (the game saw the last frame's number and ends or loops the
 * movie with BinkGoto). A game's loop is "do frame; copy; next; while
 * (!BinkWait)": it leaves only when BinkWait says wait. */
static void k_NextFrame(void) {
    bink_t *b = (bink_t *)APTR(0);
    if (b) {
        if (b->FrameNum >= b->Frames) { b->FrameNum = 1; b->wrapped = 1; }
        else {
            uint32_t f = b->st ? (b->st->ended ? b->Frames : b->st->frame + 1) : b->FrameNum + 1;
            if (f > b->Frames) f = b->Frames;
            if (f <= b->FrameNum) f = b->FrameNum + 1;
            b->FrameNum = f;
        }
    }
    RETV(1);
}
static void k_Wait(void) {                               /* nonzero while the next frame is not there yet */
    bink_t *b = (bink_t *)APTR(0);
    if (!b || !b->st) RET(0, 1);
    if (b->paused || b->wrapped) RET(1, 1);
    RET(b->st->frame == b->shown && !b->st->ended ? 1u : 0u, 1);
}
static void k_Pause(void) {                              /* (bink, pause) -> the state */
    bink_t *b = (bink_t *)APTR(0);
    int p = A32(1) != 0;
    if (!b) RET(0, 2);
    if (p != b->paused && b->st) web_movie_ctl(b->id, 1, p);
    b->paused = p;
    RET((uint32_t)p, 2);
}
static void k_SetVolume(void) {                          /* (bink, volume) 32768 is full */
    bink_t *b = (bink_t *)APTR(0);
    if (b && b->st) {
        int v = (int)((int32_t)A32(1) * 1000 / 32768);
        web_movie_ctl(b->id, 2, v < 0 ? 0 : v > 1000 ? 1000 : v);
    }
    RET(0, 2);
}
static void k_Goto(void) {                               /* (bink, frame, flags) */
    bink_t *b = (bink_t *)APTR(0);
    if (b) {
        uint32_t to = A32(1) && A32(1) <= b->Frames ? A32(1) : 1;
        b->FrameNum = to, b->shown = 0, b->wrapped = 0;
        if (b->st) { b->st->ended = 0; web_movie_ctl(b->id, 3, (int)to); }
    }
    RETV(3);
}
/* BinkCopyToBuffer(bink, dest, pitch, height, x, y, flags): the newest frame
 * into a buffer of the type flags' low bits name (565, 555, 32-bit). */
static void k_CopyToBuffer(void) {
    bink_t *b = (bink_t *)APTR(0);
    uint8_t *dst = (uint8_t *)APTR(1);
    int pitch = (int)A32(2), dh = (int)A32(3), dx = (int)A32(4), dy = (int)A32(5), type = (int)(A32(6) & 0xF);
    if (!b || !b->st || !b->st->frame || !dst) RET(0, 7);
    const uint8_t *src = (const uint8_t *)(uintptr_t)b->st->rgba;
    int w = (int)b->Width, h = (int)b->Height;
    for (int y = 0; y < h && dy + y < dh; y++) {
        const uint8_t *p = src + (size_t)y * w * 4;
        uint8_t *row = dst + (size_t)(dy + y) * (size_t)pitch;
        for (int x = 0; x < w; x++, p += 4) {
            int X = dx + x, r = p[0], g = p[1], bb = p[2];
            if (type == 10) ((uint16_t *)row)[X] = (uint16_t)((r >> 3) << 11 | (g >> 2) << 5 | bb >> 3);
            else if (type == 9) ((uint16_t *)row)[X] = (uint16_t)((r >> 3) << 10 | (g >> 3) << 5 | bb >> 3);
            else if (type == 3 || type == 5) ((uint32_t *)row)[X] = 0xFF000000u | (uint32_t)r << 16 | (uint32_t)g << 8 | (uint32_t)bb;
            else if (type == 1) row[3 * X] = (uint8_t)bb, row[3 * X + 1] = (uint8_t)g, row[3 * X + 2] = (uint8_t)r;
        }
    }
    RET(0, 7);
}
const win32hle_shim win32hle_bink[] = {
    { "_BinkOpen@8", k_Open }, { "_BinkClose@4", k_Close }, { "_BinkDoFrame@4", k_DoFrame },
    { "_BinkNextFrame@4", k_NextFrame }, { "_BinkWait@4", k_Wait }, { "_BinkCopyToBuffer@28", k_CopyToBuffer },
    { "_BinkGoto@12", k_Goto }, { "_BinkPause@8", k_Pause }, { "_BinkSetVolume@8", k_SetVolume },
    { "_BinkGetError@0", k_GetError }, { "_BinkSetSoundSystem@8", k_SetSoundSystem },
    { "_BinkOpenDirectSound@4", k_OpenDirectSound }, { "_BinkDDSurfaceType@4", k_DDSurfaceType },
    { 0, 0 } };
#elif !defined(HLE_WITH_FFMPEG)
/* No decoder: the movie "plays" without a picture. BinkOpen reads the
 * .bik's header (its size, frame count and rate), so the game gets a
 * plausible BINK and paces itself by it, and the movie ends after two
 * frames: a failed BinkOpen is not something the game copes with (Yuri's
 * Revenge dereferences the handle it did not get), and a black intro that
 * lasts its full length would be a wait for nothing. */
typedef struct {
    uint32_t Width, Height, Frames, FrameNum, LastFrameNum, FrameRate, FrameRateDiv, ReadError, OpenFlags, BinkType,
             Size, FrameSize, SndSize;
    uint32_t pad[64];
    uint32_t start_ms, paused_at;
    int paused;
} bink_t;
static void k_Open(void) {                               /* (name or handle, flags) */
    uint32_t flags = A32(1);
    uint8_t hdr[44];
    int fd, own = 0;
    if (flags & BINKFILEHANDLE) fd = hle_file_fd(A32(0));
    else {
        char path[1024];
        hle_host_path(ASTR(0), path, sizeof path);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        own = 1;
    }
    if (fd < 0) { g_error = "cannot open the movie"; RET(0, 2); }
    ssize_t n = read(fd, hdr, sizeof hdr);
    if (own) close(fd);
    if (n < (ssize_t)sizeof hdr || memcmp(hdr, "BIK", 3) != 0) { g_error = "not a Bink movie"; RET(0, 2); }
    bink_t *b = (bink_t *)hle_alloc(sizeof *b);
    memcpy(&b->Size, hdr + 4, 4);
    memcpy(&b->Frames, hdr + 8, 4);
    memcpy(&b->FrameSize, hdr + 12, 4);
    memcpy(&b->Width, hdr + 20, 4);
    memcpy(&b->Height, hdr + 24, 4);
    memcpy(&b->FrameRate, hdr + 28, 4);
    memcpy(&b->FrameRateDiv, hdr + 32, 4);
    if (!b->FrameRate) b->FrameRate = 15;
    if (!b->FrameRateDiv) b->FrameRateDiv = 1;
    (void)0; /* b->Frames as the file says */
    b->FrameNum = 1, b->OpenFlags = flags, b->start_ms = hle_ticks_ms();
    static int said;
    if (!said++) fprintf(stderr, "[bink] no movie decoder on this host: movies are skipped\n");
    RET(hle_va(b), 2);
}
static void k_Close(void) { if (A32(0)) hle_free(APTR(0)); RETV(1); }
static void k_DoFrame(void) { bink_t *b = (bink_t *)APTR(0); if (b) b->LastFrameNum = b->FrameNum; RET(0, 1); }
static void k_NextFrame(void) { bink_t *b = (bink_t *)APTR(0); if (b && b->FrameNum < b->Frames) b->FrameNum++; RETV(1); }
static void k_Wait(void) {                               /* nonzero while the next frame is not due */
    bink_t *b = (bink_t *)APTR(0);
    if (!b) RET(0, 1);
    if (b->paused) RET(1, 1);
    uint64_t due = (uint64_t)(b->FrameNum - 1) * 1000u * b->FrameRateDiv / b->FrameRate;
    RET(hle_ticks_ms() - b->start_ms < due ? 1u : 0u, 1);
}
static void k_Pause(void) {                              /* (bink, pause) -> the state */
    bink_t *b = (bink_t *)APTR(0);
    int p = A32(1) != 0;
    if (!b) RET(0, 2);
    if (p && !b->paused) b->paused_at = hle_ticks_ms();
    if (!p && b->paused) b->start_ms += hle_ticks_ms() - b->paused_at;
    b->paused = p;
    RET((uint32_t)p, 2);
}
static void k_Goto(void) {                               /* (bink, frame, flags) */
    bink_t *b = (bink_t *)APTR(0);
    if (b) {
        b->FrameNum = A32(1) && A32(1) <= b->Frames ? A32(1) : 1;
        b->start_ms = hle_ticks_ms() - (uint32_t)((uint64_t)(b->FrameNum - 1) * 1000u * b->FrameRateDiv / b->FrameRate);
    }
    RETV(3);
}
/* BinkCopyToBuffer: nothing to draw, so the buffer keeps what it had (the
 * menu's loading picture stays where its movie would play). */
static void k_CopyToBuffer(void) { RET(0, 7); }
static void k_SetVolume(void) { RET(0, 2); }
const win32hle_shim win32hle_bink[] = {
    { "_BinkOpen@8", k_Open }, { "_BinkClose@4", k_Close }, { "_BinkDoFrame@4", k_DoFrame },
    { "_BinkNextFrame@4", k_NextFrame }, { "_BinkWait@4", k_Wait }, { "_BinkCopyToBuffer@28", k_CopyToBuffer },
    { "_BinkGoto@12", k_Goto }, { "_BinkPause@8", k_Pause }, { "_BinkSetVolume@8", k_SetVolume },
    { "_BinkGetError@0", k_GetError }, { "_BinkSetSoundSystem@8", k_SetSoundSystem },
    { "_BinkOpenDirectSound@4", k_OpenDirectSound }, { "_BinkDDSurfaceType@4", k_DDSurfaceType },
    { 0, 0 } };
#else
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libswresample/swresample.h>

/* The guest-visible struct: Bink's leading fields, then ours, out of sight. */
typedef struct {
    uint32_t Width, Height, Frames, FrameNum, LastFrameNum, FrameRate, FrameRateDiv, ReadError, OpenFlags, BinkType,
             Size, FrameSize, SndSize;
    uint32_t pad[64];
    /* ours */
    int fd;
    int64_t base;                 /* where the movie starts in the file */
    AVFormatContext *fmt;
    AVIOContext *io;
    AVCodecContext *vdec, *adec;
    int vs, as;
    AVFrame *frame, *aframe;
    AVPacket *pkt;
    SwrContext *swr;
    int stream;                   /* the sound's mixer stream */
    int paused, have_frame, done;
    uint32_t start_ms, paused_at;
    float volume;
} bink_t;

static int io_read(void *opaque, uint8_t *buf, int n) {
    bink_t *b = (bink_t *)opaque;
    ssize_t r = read(b->fd, buf, (size_t)n);
    return r > 0 ? (int)r : AVERROR_EOF;
}
static int64_t io_seek(void *opaque, int64_t off, int whence) {
    bink_t *b = (bink_t *)opaque;
    if (whence == AVSEEK_SIZE) return -1;
    whence &= ~AVSEEK_FORCE;
    if (whence == SEEK_SET) off += b->base;
    off_t r = lseek(b->fd, (off_t)off, whence);
    return r < 0 ? -1 : (int64_t)r - b->base;
}

static void close_bink(bink_t *b) {
    if (b->stream >= 0) hle_audio_stream_close(b->stream);
    if (b->swr) swr_free(&b->swr);
    if (b->vdec) avcodec_free_context(&b->vdec);
    if (b->adec) avcodec_free_context(&b->adec);
    if (b->fmt) avformat_close_input(&b->fmt);
    if (b->io) { av_freep(&b->io->buffer); avio_context_free(&b->io); }
    av_frame_free(&b->frame);
    av_frame_free(&b->aframe);
    av_packet_free(&b->pkt);
    if (b->fd >= 0 && !(b->OpenFlags & BINKFILEHANDLE)) close(b->fd);
    hle_free(b);
}

static void push_audio(bink_t *b) {
    if (b->stream < 0 || !b->swr) return;
    int16_t out[8192 * 2];
    int n = swr_convert(b->swr, (uint8_t **)&(uint8_t *){ (uint8_t *)out }, 8192, (const uint8_t **)b->aframe->extended_data,
                        b->aframe->nb_samples);
    if (n > 0) hle_audio_stream_push(b->stream, out, n);
}

/* Read packets until the next video frame is decoded; sound met on the way
 * goes to the mixer. */
static int decode_frame(bink_t *b) {
    for (;;) {
        int r = avcodec_receive_frame(b->vdec, b->frame);
        if (r == 0) return 1;
        if (r != AVERROR(EAGAIN)) return 0;
        if (av_read_frame(b->fmt, b->pkt) < 0) { avcodec_send_packet(b->vdec, NULL); b->done = 1; continue; }
        if (b->pkt->stream_index == b->vs) avcodec_send_packet(b->vdec, b->pkt);
        else if (b->adec && b->pkt->stream_index == b->as && avcodec_send_packet(b->adec, b->pkt) == 0)
            while (avcodec_receive_frame(b->adec, b->aframe) == 0) push_audio(b);
        av_packet_unref(b->pkt);
        if (b->done) return 0;
    }
}

static void k_Open(void) {                               /* (name or handle, flags) */
    uint32_t flags = A32(1);
    bink_t *b = (bink_t *)hle_alloc(sizeof *b);          /* the guest reads its leading fields */
    b->stream = -1, b->volume = 1.0f, b->fd = -1;
    if (flags & BINKFILEHANDLE) {
        b->fd = hle_file_fd(A32(0));
        b->base = b->fd >= 0 ? lseek(b->fd, 0, SEEK_CUR) : 0;
    } else {
        char path[1024];
        hle_host_path(ASTR(0), path, sizeof path);
        b->fd = open(path, O_RDONLY | O_CLOEXEC);
    }
    b->OpenFlags = flags;
    if (b->fd < 0) { g_error = "cannot open the movie"; hle_free(b); RET(0, 2); }
    b->io = avio_alloc_context((uint8_t *)av_malloc(65536), 65536, 0, b, io_read, NULL, io_seek);
    b->fmt = avformat_alloc_context();
    b->fmt->pb = b->io;
    const AVInputFormat *bik = av_find_input_format("bink");
    if (avformat_open_input(&b->fmt, NULL, bik, NULL) < 0 || avformat_find_stream_info(b->fmt, NULL) < 0) {
        g_error = "not a Bink movie";
        b->fmt = NULL;
        close_bink(b);
        RET(0, 2);
    }
    b->vs = av_find_best_stream(b->fmt, AVMEDIA_TYPE_VIDEO, -1, -1, NULL, 0);
    b->as = av_find_best_stream(b->fmt, AVMEDIA_TYPE_AUDIO, -1, -1, NULL, 0);
    if (b->vs < 0) { g_error = "no video in the movie"; close_bink(b); RET(0, 2); }
    AVStream *v = b->fmt->streams[b->vs];
    const AVCodec *vc = avcodec_find_decoder(v->codecpar->codec_id);
    b->vdec = avcodec_alloc_context3(vc);
    avcodec_parameters_to_context(b->vdec, v->codecpar);
    if (!vc || avcodec_open2(b->vdec, vc, NULL) < 0) { g_error = "no Bink video decoder"; close_bink(b); RET(0, 2); }
    if (b->as >= 0) {
        AVStream *a = b->fmt->streams[b->as];
        const AVCodec *ac = avcodec_find_decoder(a->codecpar->codec_id);
        b->adec = ac ? avcodec_alloc_context3(ac) : NULL;
        if (b->adec) {
            avcodec_parameters_to_context(b->adec, a->codecpar);
            if (avcodec_open2(b->adec, ac, NULL) < 0) avcodec_free_context(&b->adec);
        }
        if (b->adec) {
            int ch = b->adec->ch_layout.nb_channels > 1 ? 2 : 1;
            AVChannelLayout out = ch == 2 ? (AVChannelLayout)AV_CHANNEL_LAYOUT_STEREO : (AVChannelLayout)AV_CHANNEL_LAYOUT_MONO;
            swr_alloc_set_opts2(&b->swr, &out, AV_SAMPLE_FMT_S16, b->adec->sample_rate, &b->adec->ch_layout,
                                b->adec->sample_fmt, b->adec->sample_rate, 0, NULL);
            if (b->swr && swr_init(b->swr) == 0) b->stream = hle_audio_stream_open(b->adec->sample_rate, ch);
        }
    }
    b->frame = av_frame_alloc(), b->aframe = av_frame_alloc(), b->pkt = av_packet_alloc();
    b->Width = (uint32_t)v->codecpar->width, b->Height = (uint32_t)v->codecpar->height;
    b->Frames = v->nb_frames > 0 ? (uint32_t)v->nb_frames : (uint32_t)v->duration;
    b->FrameRate = (uint32_t)v->avg_frame_rate.num, b->FrameRateDiv = (uint32_t)(v->avg_frame_rate.den ? v->avg_frame_rate.den : 1);
    if (!b->FrameRate) b->FrameRate = 15, b->FrameRateDiv = 1;
    b->FrameNum = 1, b->LastFrameNum = 0;
    b->start_ms = hle_ticks_ms();
    fprintf(stderr, "[bink] %ux%u, %u frames at %u/%u fps%s\n", b->Width, b->Height, b->Frames, b->FrameRate,
            b->FrameRateDiv, b->stream >= 0 ? ", with sound" : "");
    RETP(b, 2);
}
static void k_Close(void) { if (A32(0)) close_bink((bink_t *)APTR(0)); RETV(1); }

static void k_DoFrame(void) {                            /* decode the current frame */
    bink_t *b = (bink_t *)APTR(0);
    b->have_frame = decode_frame(b);
    b->LastFrameNum = b->FrameNum;
    RET(0, 1);
}
static void k_NextFrame(void) {
    bink_t *b = (bink_t *)APTR(0);
    if (b->FrameNum < b->Frames) b->FrameNum++;
    RETV(1);
}
/* BinkWait: nonzero while it is not yet time for the next frame. */
static void k_Wait(void) {
    bink_t *b = (bink_t *)APTR(0);
    if (b->paused) RET(1, 1);
    uint64_t due = (uint64_t)(b->FrameNum - 1) * 1000u * b->FrameRateDiv / b->FrameRate;
    RET(hle_ticks_ms() - b->start_ms < due ? 1u : 0u, 1);
}
static void k_Pause(void) {                              /* (bink, pause) -> the state */
    bink_t *b = (bink_t *)APTR(0);
    int p = A32(1) != 0;
    if (p && !b->paused) b->paused_at = hle_ticks_ms();
    if (!p && b->paused) b->start_ms += hle_ticks_ms() - b->paused_at;
    b->paused = p;
    if (b->stream >= 0) hle_audio_stream_gain(b->stream, p ? 0.0f : b->volume);
    RET((uint32_t)p, 2);
}
static void k_SetVolume(void) {                          /* (bink, volume) 32768 is full */
    bink_t *b = (bink_t *)APTR(0);
    b->volume = (float)(int32_t)A32(1) / 32768.0f;
    if (b->volume > 1.0f) b->volume = 1.0f;
    if (b->stream >= 0 && !b->paused) hle_audio_stream_gain(b->stream, b->volume);
    RETV(2);
}
/* BinkGoto(bink, frame, flags): back to the start, then forward. The start by
 * the demuxer's own seek, to its first key frame: AVSEEK_FLAG_BYTE would go
 * round it and leave its frame count where it was, at the end after a whole
 * movie, with nothing more to read. The sound queued from before the seek is
 * dropped, as is what the frames passed over bring. */
static void k_Goto(void) {
    bink_t *b = (bink_t *)APTR(0);
    uint32_t to = A32(1) ? A32(1) : 1;
    int stream = -1;
    if (av_seek_frame(b->fmt, b->vs, 0, AVSEEK_FLAG_BACKWARD) < 0) g_error = "cannot seek in the movie";
    avcodec_flush_buffers(b->vdec);
    if (b->adec) avcodec_flush_buffers(b->adec);
    if (b->stream >= 0) {
        hle_audio_stream_close(b->stream);
        stream = hle_audio_stream_open(b->adec->sample_rate, b->adec->ch_layout.nb_channels > 1 ? 2 : 1);
        if (stream >= 0) hle_audio_stream_gain(stream, b->paused ? 0.0f : b->volume);
    }
    b->stream = -1;
    b->done = 0, b->FrameNum = 1;
    while (b->FrameNum < to && decode_frame(b)) b->FrameNum++;
    b->stream = stream;
    b->start_ms = b->paused_at = hle_ticks_ms();
    b->start_ms -= (uint32_t)((uint64_t)(b->FrameNum - 1) * 1000u * b->FrameRateDiv / b->FrameRate);
    RETV(3);
}

/* BinkCopyToBuffer(bink, dest, pitch, height, x, y, flags): the decoded frame
 * into a buffer of the type flags' low bits name (565, 555, 32-bit). */
static void k_CopyToBuffer(void) {
    bink_t *b = (bink_t *)APTR(0);
    uint8_t *dst = (uint8_t *)APTR(1);
    int pitch = (int)A32(2), dh = (int)A32(3), dx = (int)A32(4), dy = (int)A32(5), type = (int)(A32(6) & 0xF);
    AVFrame *f = b->frame;
    if (!b->have_frame || !dst || f->format != AV_PIX_FMT_YUV420P) RET(0, 7);
    int w = f->width, h = f->height;
    for (int y = 0; y < h && dy + y < dh; y++) {
        const uint8_t *Y = f->data[0] + y * f->linesize[0], *U = f->data[1] + (y / 2) * f->linesize[1], *V = f->data[2] + (y / 2) * f->linesize[2];
        uint8_t *row = dst + (size_t)(dy + y) * (size_t)pitch;
        for (int x = 0; x < w; x++) {
            int c = Y[x] - 16, d = U[x / 2] - 128, e = V[x / 2] - 128;
            int r = (298 * c + 409 * e + 128) >> 8, g = (298 * c - 100 * d - 208 * e + 128) >> 8, bb = (298 * c + 516 * d + 128) >> 8;
            r = r < 0 ? 0 : r > 255 ? 255 : r, g = g < 0 ? 0 : g > 255 ? 255 : g, bb = bb < 0 ? 0 : bb > 255 ? 255 : bb;
            int X = dx + x;
            if (type == 10) ((uint16_t *)row)[X] = (uint16_t)((r >> 3) << 11 | (g >> 2) << 5 | bb >> 3);
            else if (type == 9) ((uint16_t *)row)[X] = (uint16_t)((r >> 3) << 10 | (g >> 3) << 5 | bb >> 3);
            else if (type == 3 || type == 5) ((uint32_t *)row)[X] = 0xFF000000u | (uint32_t)r << 16 | (uint32_t)g << 8 | (uint32_t)bb;
        }
    }
    RET(0, 7);
}

/* ---- BinkBuffer: where a GDI game has Bink put the picture ----
 * The game locks the buffer, has BinkCopyToBuffer fill it at its
 * SurfaceType, and blits it to its window at the offset it set: here a
 * 32-bit buffer, blitted onto the window surface (gdidc.c). The leading
 * fields are Bink's BINKBUFFER, which games read. */
typedef struct {
    uint32_t Width, Height, WindowWidth, WindowHeight, SurfaceType, Buffer;
    int32_t BufferPitch;
    uint32_t ClientOffsetX, ClientOffsetY, ScreenWidth, ScreenHeight, ScreenDepth;
    uint32_t pad[48];
    int destx, desty;                                    /* ours */
} binkbuf_t;
static void k_BufferOpen(void) {                         /* (hwnd, width, height, flags) */
    binkbuf_t *b = (binkbuf_t *)hle_alloc(sizeof *b);   /* the game reads its fields */
    int sw, sh;
    const uint8_t *px; int pitch, bpp;
    b->Width = b->WindowWidth = A32(1), b->Height = b->WindowHeight = A32(2);
    b->SurfaceType = 3;                                  /* BINKSURFACE32 */
    b->BufferPitch = (int32_t)(b->Width * 4);
    b->Buffer = hle_va(hle_alloc((b->Width * b->Height + 1) * 4u));
    if (hle_gdi_window_frame(&px, &sw, &sh, &pitch, &bpp, NULL)) b->ScreenWidth = (uint32_t)sw, b->ScreenHeight = (uint32_t)sh, b->ScreenDepth = (uint32_t)bpp;
    RETP(b, 4);
}
static void k_BufferClose(void) {
    binkbuf_t *b = (binkbuf_t *)APTR(0);
    if (b) hle_free(hle_ptr(b->Buffer)), hle_free(b);
    RETV(1);
}
static void k_BufferLock(void) { RET(A32(0) != 0, 1); }
static void k_BufferUnlock(void) { RET(1, 1); }
static void k_BufferSetOffset(void) {                    /* (buf, x, y) */
    binkbuf_t *b = (binkbuf_t *)APTR(0);
    if (b) b->destx = (int)A32(1), b->desty = (int)A32(2);
    RET(1, 3);
}
static void k_BufferBlit(void) {                         /* (buf, rects, n): the whole picture, whatever changed */
    binkbuf_t *b = (binkbuf_t *)APTR(0);
    const uint8_t *px;
    int sw, sh, pitch, bpp;
    if (b && hle_gdi_window_frame(&px, &sw, &sh, &pitch, &bpp, NULL) && bpp == 32) {
        for (int y = 0; y < (int)b->Height; y++) {
            int ty = b->desty + y;
            if (ty < 0 || ty >= sh) continue;
            for (int x = 0; x < (int)b->Width; x++) {
                int tx = b->destx + x;
                if (tx >= 0 && tx < sw)
                    ((uint32_t *)(px + (size_t)ty * pitch))[tx] = ((const uint32_t *)hle_ptr(b->Buffer))[(size_t)y * b->Width + x] & 0xFFFFFFu;
            }
        }
        hle_gdi_window_touched();
    }
    RETV(3);
}
static void k_GetRects(void) { RET(1, 2); }              /* (bink, flags): one rectangle, the whole frame */
static void k_SetIOSize(void) { RETV(1); }

const win32hle_shim win32hle_bink[] = {
    { "_BinkBufferOpen@16", k_BufferOpen }, { "_BinkBufferClose@4", k_BufferClose },
    { "_BinkBufferLock@4", k_BufferLock }, { "_BinkBufferUnlock@4", k_BufferUnlock },
    { "_BinkBufferSetOffset@12", k_BufferSetOffset }, { "_BinkBufferBlit@12", k_BufferBlit },
    { "_BinkGetRects@8", k_GetRects }, { "_BinkSetIOSize@4", k_SetIOSize },
    { "_BinkOpen@8", k_Open }, { "_BinkClose@4", k_Close }, { "_BinkDoFrame@4", k_DoFrame },
    { "_BinkNextFrame@4", k_NextFrame }, { "_BinkWait@4", k_Wait }, { "_BinkCopyToBuffer@28", k_CopyToBuffer },
    { "_BinkGoto@12", k_Goto }, { "_BinkPause@8", k_Pause }, { "_BinkSetVolume@8", k_SetVolume },
    { "_BinkGetError@0", k_GetError }, { "_BinkSetSoundSystem@8", k_SetSoundSystem },
    { "_BinkOpenDirectSound@4", k_OpenDirectSound }, { "_BinkDDSurfaceType@4", k_DDSurfaceType },
    { 0, 0 } };
#endif
