/*
 * mss.c - the part of Miles (mss32.dll, RAD's Miles Sound System 6) that a
 * game's own audio DLL calls: its file and memory helpers, and the RIB
 * provider lookup that hands out an ASI codec, here an MP3 decoder on ffmpeg.
 *
 * Civilization III's sound.dll streams its music this way: it finds the
 * provider for "ASI codec" / "Input file types" by the file's name, asks it
 * (RIB_request_interface) for the "ASI stream" functions and attribute ids,
 * opens a stream with a callback that hands over the compressed bytes, and
 * pulls 16-bit PCM out with ASI_stream_process into its DirectSound buffers.
 *
 * In this Miles a RIB_INTERFACE_ENTRY is { type, name, token, subtype } and
 * token is where the answer goes: a function's address, or an attribute's
 * id. Everything here is stdcall. Without HLE_WITH_FFMPEG there is no
 * provider, as with a Miles install missing its MP3 codec.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "win32hle.h"

/* ---- files and memory ---- */
static void a_startup(void) { RET(1, 0); }
static void a_shutdown(void) { RETV(0); }
static void a_set_redist_directory(void) { static char dir[260]; RETP(dir, 1); }   /* the previous one */
static void a_mem_alloc_lock(void) { RETP(hle_alloc(A32(0)), 1); }
static void a_mem_free_lock(void) { hle_free(APTR(0)); RETV(1); }
static long whole_file(const char *name, void *dest, void **out) {   /* its size; read into dest or a new block */
    char host[1024];
    FILE *f = name && hle_host_path(name, host, sizeof host) ? fopen(host, "rb") : NULL;
    long n = -1;
    if (f && fseek(f, 0, SEEK_END) == 0) n = ftell(f), rewind(f);
    if (f && out && n >= 0) {
        *out = dest ? dest : hle_alloc((uint32_t)n);
        if (*out && fread(*out, 1, (size_t)n, f) != (size_t)n) { if (!dest) hle_free(*out); *out = NULL; }
    }
    if (f) fclose(f);
    return n;
}
static void a_file_size(void) { RET((uint32_t)whole_file(ASTR(0), NULL, NULL), 1); }
static void a_file_read(void) {                          /* (name, dest): dest NULL makes a block */
    void *p = NULL;
    whole_file(ASTR(0), APTR(1), &p);
    RETP(p, 2);
}

#ifndef HLE_WITH_FFMPEG
static void r_find_file_provider(void) { RET(0, 3); }
static void r_request_interface(void) { RET(1, 4); }
#else
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libswresample/swresample.h>
#include <libavutil/opt.h>

/* Attributes and preferences, by the names a caller asks for: the id is the
 * index here. */
enum { IN_BITRATE = 1, IN_RATE, IN_WIDTH, IN_CHANNELS, OUT_BITRATE, OUT_RATE, OUT_WIDTH, OUT_CHANNELS, POSITION,
       PERCENT, MIN_BLOCK, RAW_RATE, RAW_WIDTH, RAW_CHANNELS, REQ_BITRATE, REQ_RATE, REQ_WIDTH, REQ_CHANNELS, LAYER, NATTR };
static const char *const k_attr[NATTR] = { "", "Input bit rate", "Input sample rate", "Input sample width", "Input channels",
    "Output bit rate", "Output sample rate", "Output sample width", "Output channels", "Position", "Percent done",
    "Minimum input block size", "Raw source sample rate", "Raw source sample width", "Raw source channels",
    "Requested bit rate", "Requested sample rate", "Requested sample width", "Requested channels", "Layer" };

typedef struct {
    uint32_t user, fetch, total, pos;                    /* the caller's: its fetch callback reads its file */
    int32_t pref[NATTR];
    AVFormatContext *fmt;
    AVIOContext *io;
    AVCodecContext *dec;
    SwrContext *swr;
    AVFrame *frame;
    AVPacket *pkt;
    int as, rate, channels, eof;
    int16_t *pcm;                                        /* decoded and not yet handed out */
    int pcm_n, pcm_at, pcm_cap;
    uint8_t *fetch_buf;                                  /* guest-visible: the callback writes into it */
} asi_t;

/* S32 fetch(U32 user, void *dest, S32 bytes, S32 offset): offset -1 reads on. */
/* Never past the stream's end: the caller's callback copies what is asked
 * from its own buffer (Civilization III's sound.dll ran off its end). */
static int io_read(void *opaque, uint8_t *buf, int n) {
    asi_t *s = (asi_t *)opaque;
    if (n > 65536) n = 65536;
    if (s->total && s->pos >= s->total) return AVERROR_EOF;
    if (s->total && (uint32_t)n > s->total - s->pos) n = (int)(s->total - s->pos);
    uint32_t a[4] = { s->user, (uint32_t)(uintptr_t)s->fetch_buf, (uint32_t)n, s->pos };
    int got = (int)hle_call_guest(s->fetch, 4, a);
    if (got <= 0) return AVERROR_EOF;
    memcpy(buf, s->fetch_buf, (size_t)got);
    s->pos += (uint32_t)got;
    return got;
}
static int64_t io_seek(void *opaque, int64_t off, int whence) {
    asi_t *s = (asi_t *)opaque;
    whence &= ~AVSEEK_FORCE;
    if (whence == AVSEEK_SIZE) return s->total ? (int64_t)s->total : -1;
    int64_t to = whence == SEEK_SET ? off : whence == SEEK_CUR ? s->pos + off : whence == SEEK_END && s->total ? s->total + off : -1;
    if (to < 0 || (s->total && to > s->total)) return -1;
    s->pos = (uint32_t)to;
    return to;
}

static void asi_free(asi_t *s) {
    if (s->swr) swr_free(&s->swr);
    if (s->dec) avcodec_free_context(&s->dec);
    if (s->fmt) avformat_close_input(&s->fmt);
    if (s->io) { av_freep(&s->io->buffer); avio_context_free(&s->io); }
    av_frame_free(&s->frame);
    av_packet_free(&s->pkt);
    free(s->pcm), free(s->fetch_buf), free(s);
}

/* The output: what the caller requested, else the stream's own. */
static int out_rate(const asi_t *s) { return s->pref[REQ_RATE] > 0 ? s->pref[REQ_RATE] : s->rate; }
static int out_channels(const asi_t *s) { return s->pref[REQ_CHANNELS] == 1 || s->pref[REQ_CHANNELS] == 2 ? s->pref[REQ_CHANNELS] : s->channels; }

static int setup_swr(asi_t *s) {
    if (s->swr) swr_free(&s->swr);
    AVChannelLayout out = out_channels(s) == 2 ? (AVChannelLayout)AV_CHANNEL_LAYOUT_STEREO : (AVChannelLayout)AV_CHANNEL_LAYOUT_MONO;
    swr_alloc_set_opts2(&s->swr, &out, AV_SAMPLE_FMT_S16, out_rate(s), &s->dec->ch_layout, s->dec->sample_fmt, s->dec->sample_rate, 0, NULL);
    return s->swr && swr_init(s->swr) == 0;
}

/* Decode until there is PCM to hand out, or the stream has ended. */
static int refill(asi_t *s) {
    while (s->pcm_at >= s->pcm_n && !s->eof) {
        int r = avcodec_receive_frame(s->dec, s->frame);
        if (r == 0) {
            if (!s->swr && !setup_swr(s)) { s->eof = 1; break; }
            int max = swr_get_out_samples(s->swr, s->frame->nb_samples), ch = out_channels(s);
            if (max * ch > s->pcm_cap) s->pcm_cap = max * ch, s->pcm = (int16_t *)realloc(s->pcm, (size_t)s->pcm_cap * 2);
            uint8_t *o = (uint8_t *)s->pcm;
            int n = swr_convert(s->swr, &o, max, (const uint8_t **)s->frame->extended_data, s->frame->nb_samples);
            s->pcm_n = n > 0 ? n * ch : 0, s->pcm_at = 0;
            continue;
        }
        if (r != AVERROR(EAGAIN)) { s->eof = 1; break; }
        if (av_read_frame(s->fmt, s->pkt) < 0) { avcodec_send_packet(s->dec, NULL); continue; }
        if (s->pkt->stream_index == s->as) avcodec_send_packet(s->dec, s->pkt);
        av_packet_unref(s->pkt);
    }
    return s->pcm_at < s->pcm_n;
}

static void s_open(void) {                               /* (user, fetch_cb, total_size) -> stream */
    asi_t *s = (asi_t *)calloc(1, sizeof *s);
    s->user = A32(0), s->fetch = A32(1), s->total = A32(2);
    s->fetch_buf = (uint8_t *)malloc(65536);
    s->io = avio_alloc_context((uint8_t *)av_malloc(65536), 65536, 0, s, io_read, NULL, io_seek);
    s->fmt = avformat_alloc_context();
    s->fmt->pb = s->io;
    if (avformat_open_input(&s->fmt, NULL, av_find_input_format("mp3"), NULL) < 0 || avformat_find_stream_info(s->fmt, NULL) < 0) {
        fprintf(stderr, "[mss] ASI_stream_open: not an MP3 stream\n");
        s->fmt = NULL;
        asi_free(s);
        RET(0, 3);
    }
    s->as = av_find_best_stream(s->fmt, AVMEDIA_TYPE_AUDIO, -1, -1, NULL, 0);
    const AVCodec *c = s->as >= 0 ? avcodec_find_decoder(s->fmt->streams[s->as]->codecpar->codec_id) : NULL;
    s->dec = c ? avcodec_alloc_context3(c) : NULL;
    if (!s->dec || avcodec_parameters_to_context(s->dec, s->fmt->streams[s->as]->codecpar) < 0 || avcodec_open2(s->dec, c, NULL) < 0) {
        fprintf(stderr, "[mss] ASI_stream_open: no MP3 decoder\n");
        asi_free(s);
        RET(0, 3);
    }
    s->rate = s->dec->sample_rate, s->channels = s->dec->ch_layout.nb_channels > 1 ? 2 : 1;
    s->frame = av_frame_alloc(), s->pkt = av_packet_alloc();
    RETP(s, 3);
}
static void s_process(void) {                            /* (stream, buffer, bytes) -> bytes written */
    asi_t *s = (asi_t *)APTR(0);
    int16_t *out = (int16_t *)APTR(1);
    int want = (int)A32(2) / 2, n = 0;
    while (s && n < want && refill(s)) {
        int k = s->pcm_n - s->pcm_at < want - n ? s->pcm_n - s->pcm_at : want - n;
        memcpy(out + n, s->pcm + s->pcm_at, (size_t)k * 2);
        n += k, s->pcm_at += k;
    }
    RET((uint32_t)n * 2, 3);
}
static void s_seek(void) {                               /* (stream, offset): back to the start, or on from a byte */
    asi_t *s = (asi_t *)APTR(0);
    int32_t off = (int32_t)A32(1);
    if (s) {
        if (off >= 0) av_seek_frame(s->fmt, s->as, off, AVSEEK_FLAG_BYTE | AVSEEK_FLAG_BACKWARD);
        avcodec_flush_buffers(s->dec);
        s->eof = 0, s->pcm_n = s->pcm_at = 0;
    }
    RET(0, 2);
}
static void s_attribute(void) {                          /* (stream, attribute id) -> its value */
    asi_t *s = (asi_t *)APTR(0);
    uint32_t a = A32(1), v = 0;
    if (s) switch (a) {
        case IN_BITRATE: v = (uint32_t)(s->dec->bit_rate > 0 ? s->dec->bit_rate : 128000); break;
        case IN_RATE: v = (uint32_t)s->rate; break;
        case IN_WIDTH: case OUT_WIDTH: v = 16; break;
        case IN_CHANNELS: v = (uint32_t)s->channels; break;
        case OUT_BITRATE: v = (uint32_t)(out_rate(s) * out_channels(s) * 16); break;
        case OUT_RATE: v = (uint32_t)out_rate(s); break;
        case OUT_CHANNELS: v = (uint32_t)out_channels(s); break;
        case POSITION: v = s->pos; break;
        case PERCENT: v = s->total ? (uint32_t)((uint64_t)s->pos * 100 / s->total) : 0; break;
        case MIN_BLOCK: v = 4096; break;
        default: if (a < NATTR) v = (uint32_t)s->pref[a];
    }
    RET(v, 2);
}
static void s_set_preference(void) {                     /* (stream, preference id, &value) -> the previous */
    asi_t *s = (asi_t *)APTR(0);
    uint32_t p = A32(1), prev = 0;
    if (s && p < NATTR && A32(2)) {
        prev = (uint32_t)s->pref[p], s->pref[p] = (int32_t)MEM32(A32(2));
        if (s->swr && (p == REQ_RATE || p == REQ_CHANNELS)) swr_free(&s->swr);   /* the output changed: set up again */
    }
    RET(prev, 3);
}
static void s_close(void) { if (A32(0)) asi_free((asi_t *)APTR(0)); RET(0, 1); }
static void s_error(void) { static char none[] = ""; RETP(none, 0); }

static const win32hle_shim g_asi[] = {
    { "mss:ASI_stream_open", s_open }, { "mss:ASI_stream_process", s_process }, { "mss:ASI_stream_seek", s_seek },
    { "mss:ASI_stream_attribute", s_attribute }, { "mss:ASI_stream_set_preference", s_set_preference },
    { "mss:ASI_stream_close", s_close }, { "mss:ASI_error", s_error }, { 0, 0 } };

/* RIB_find_file_provider(interface, property, file name): the MP3 codec. */
#define MP3_PROVIDER 0x4D503301u
static void r_find_file_provider(void) {
    const char *iface = ASTR(0), *name = ASTR(2);
    const char *dot = name ? strrchr(name, '.') : NULL;
    RET(iface && !strcmp(iface, "ASI codec") && dot && !strcasecmp(dot, ".mp3") ? MP3_PROVIDER : 0u, 3);
}
/* RIB_request_interface(provider, interface, count, entries): each entry's
 * answer stored where its token points. */
static void r_request_interface(void) {
    static int registered;
    if (!registered) win32hle_register(g_asi), registered = 1;
    uint32_t list = A32(3);
    if (A32(0) != MP3_PROVIDER) RET(1, 4);               /* RIB_NOT_FOUND */
    for (uint32_t i = 0; i < A32(2); i++) {
        uint32_t e = list + 16 * i, type = MEM32(e), token = MEM32(e + 8), v = 0;
        const char *name = (const char *)(uintptr_t)MEM32(e + 4);
        if (type == 0) {                                 /* RIB_FUNCTION */
            char full[64];
            snprintf(full, sizeof full, "mss:%s", name);
            v = hle_resolve(full);
        } else {
            for (uint32_t k = 1; k < NATTR; k++) if (!strcmp(name, k_attr[k])) v = k;
        }
        if (!v) fprintf(stderr, "[mss] %s has no \"%s\"\n", ASTR(1), name);
        if (token) MEM32(token) = v;
    }
    RET(0, 4);
}
#endif

const win32hle_shim win32hle_mss[] = {
    { "_AIL_startup@0", a_startup }, { "_AIL_shutdown@0", a_shutdown },
    { "_AIL_set_redist_directory@4", a_set_redist_directory },
    { "_AIL_mem_alloc_lock@4", a_mem_alloc_lock }, { "_AIL_mem_free_lock@4", a_mem_free_lock },
    { "_AIL_file_size@4", a_file_size }, { "_AIL_file_read@8", a_file_read },
    { "RIB_find_file_provider", r_find_file_provider }, { "RIB_request_interface", r_request_interface },
    { 0, 0 }
};
