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
static void k_GetError(void) { RETP(g_error, 0); }
static void k_SetSoundSystem(void) { RET(1, 2); }        /* (open, param): DirectSound, which is ours */
static void k_OpenDirectSound(void) { RET(0, 1); }
/* BinkDDSurfaceType(surface): the BINKSURFACE type of a DirectDraw surface */
static void k_DDSurfaceType(void) {
    uint8_t *px;
    int w, h, pitch, bpp;
    if (!hle_dd_surface_pixels(A32(0), &px, &w, &h, &pitch, &bpp)) RET(0xFFFFFFFFu, 1);
    RET(bpp == 16 ? 10u /* 565 */ : bpp == 32 ? 3u /* 32 */ : bpp == 24 ? 1u : 0u, 1);
}

#ifndef HLE_WITH_FFMPEG
static void k_Open(void) { g_error = "no movie decoder on this host"; RET(0, 2); }
static void k_ret0_1(void) { RET(0, 1); }
static void k_ret0_2(void) { RET(0, 2); }
static void k_ret0_3(void) { RET(0, 3); }
static void k_ret0_7(void) { RET(0, 7); }
const win32hle_shim win32hle_bink[] = {
    { "_BinkOpen@8", k_Open }, { "_BinkClose@4", k_ret0_1 }, { "_BinkDoFrame@4", k_ret0_1 },
    { "_BinkNextFrame@4", k_ret0_1 }, { "_BinkWait@4", k_ret0_1 }, { "_BinkCopyToBuffer@28", k_ret0_7 },
    { "_BinkGoto@12", k_ret0_3 }, { "_BinkPause@8", k_ret0_2 }, { "_BinkSetVolume@8", k_ret0_2 },
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
    free(b);
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
    bink_t *b = (bink_t *)calloc(1, sizeof *b);
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
    if (b->fd < 0) { g_error = "cannot open the movie"; free(b); RET(0, 2); }
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
static void k_Goto(void) {                               /* (bink, frame, flags): back to the start, then forward */
    bink_t *b = (bink_t *)APTR(0);
    uint32_t to = A32(1) ? A32(1) : 1;
    av_seek_frame(b->fmt, b->vs, 0, AVSEEK_FLAG_BACKWARD | AVSEEK_FLAG_BYTE);
    avcodec_flush_buffers(b->vdec);
    b->done = 0, b->FrameNum = 1;
    while (b->FrameNum < to && decode_frame(b)) b->FrameNum++;
    b->start_ms = hle_ticks_ms() - (uint32_t)((uint64_t)(b->FrameNum - 1) * 1000u * b->FrameRateDiv / b->FrameRate);
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

const win32hle_shim win32hle_bink[] = {
    { "_BinkOpen@8", k_Open }, { "_BinkClose@4", k_Close }, { "_BinkDoFrame@4", k_DoFrame },
    { "_BinkNextFrame@4", k_NextFrame }, { "_BinkWait@4", k_Wait }, { "_BinkCopyToBuffer@28", k_CopyToBuffer },
    { "_BinkGoto@12", k_Goto }, { "_BinkPause@8", k_Pause }, { "_BinkSetVolume@8", k_SetVolume },
    { "_BinkGetError@0", k_GetError }, { "_BinkSetSoundSystem@8", k_SetSoundSystem },
    { "_BinkOpenDirectSound@4", k_OpenDirectSound }, { "_BinkDDSurfaceType@4", k_DDSurfaceType },
    { 0, 0 } };
#endif
