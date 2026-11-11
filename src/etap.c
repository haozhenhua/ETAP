#define _POSIX_C_SOURCE 200809L

#include "etap.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_SLOTS 32
#define DEFAULT_SLOTS 8
#define MAX_RANGES 8
#define MAX_FIELDS 16
#define MAX_FEATURES 16
#define MAX_PROTOS 8
#define DEFAULT_MAX_RECORDS 32
#define DEFAULT_MAX_BYTES (128u * 1024u)
#define SIM_T0_NS 1000000000000ull
#define PKT_IAT_NS 1000000ull

enum { SLOT_EMPTY = 0, SLOT_READY = 1, SLOT_LEASED = 2 };

typedef struct {
    uint32_t meta_mask;
    uint8_t  bytes_mode;
    uint8_t  n_ranges;
    uint16_t max_bytes;
    etap_byte_range ranges[MAX_RANGES];
} packet_sel;

typedef struct {
    uint16_t flags;
    uint16_t n_fields;
    uint32_t field_ids[MAX_FIELDS];
} parse_sel;

typedef struct {
    uint16_t event_mask;
    uint16_t flags;
    uint16_t n_features;
    uint32_t feature_ids[MAX_FEATURES];
} flow_sel;

typedef struct {
    uint32_t flags;
    uint32_t view_mask;
    uint32_t max_records;
    uint32_t max_bytes;
    uint32_t max_wait_us;
    uint32_t budget_rps;
    uint64_t budget_bps;
    uint8_t  overflow;
    uint8_t  sample_mode;
    uint32_t sample_n;
    packet_sel packet;
    parse_sel  parse;
    flow_sel   flow;
} sub_cfg;

typedef struct {
    int state;
    uint8_t *buf;
    uint32_t cap;
    uint32_t size;
    uint64_t batch_id;
} slot;

typedef struct {
    uint64_t flow_id;
    uint8_t  alive;
    uint8_t  kind; /* 0 http, 1 tls+sni, 2 tls no sni + trunc */
    uint32_t ifindex;
    uint32_t src, dst;
    uint16_t sport, dport;
    uint64_t start_ns;
    uint64_t last_ns;
    uint64_t pkt_id_first;
    uint64_t pkt_id_last;
    uint64_t pkts_fwd, pkts_rev;
    uint64_t bytes_fwd, bytes_rev;
    uint32_t emitted;
} sim_flow;

struct etap_caps {
    uint8_t *buf;
    uint32_t len;
};

struct etap_schema {
    uint32_t schema_id;
    uint32_t epoch;
};

struct etap_batch {
    struct etap_sub *sub;
    int slot_index;
    uint8_t *buf;
    uint32_t size;
    struct etap_schema schema;
};

struct etap_conn {
    int closed;
    uint32_t port_id;
    uint32_t next_sub_id;
    uint32_t slots_pref;
};

struct etap_sub {
    struct etap_conn *conn;
    int closed;
    uint64_t sub_id;
    uint32_t epoch;
    uint32_t schema_id;
    sub_cfg cfg;
    pthread_mutex_t mu;

    uint32_t n_slots;
    slot slots[MAX_SLOTS];

    uint64_t next_batch_id;
    uint64_t seq;
    uint64_t next_pkt_id;
    uint64_t next_flow_id;
    uint64_t now_ns;

    uint64_t pending_gap_pkts;
    uint64_t pending_gap_bytes;
    uint64_t pending_gap_first;
    uint64_t pending_gap_last;

    uint64_t delivered_batches;
    uint64_t delivered_pkts;
    uint64_t dropped_pkts;
    uint64_t dropped_bytes;
    uint64_t leased_batches;

    uint32_t pkt_limit;     /* 0 = unlimited */
    uint32_t pkt_emitted;
    int      exhausted;

    sim_flow flows[3];
    uint32_t cycle;
    int      schema_needs_embed;

    struct etap_schema last_schema;
};

/* ---- catalog ---- */

static const char *k_proto_names[] = { "eth", "ipv4", "tcp", "tls", "http" };
static const uint32_t k_proto_ids[] = {
    ETAP_PROTO_ETH, ETAP_PROTO_IPV4, ETAP_PROTO_TCP, ETAP_PROTO_TLS, ETAP_PROTO_HTTP
};
static const uint32_t k_proto_parent[] = { 0, ETAP_PROTO_ETH, ETAP_PROTO_IPV4, ETAP_PROTO_TCP, ETAP_PROTO_TCP };

typedef struct {
    uint32_t id, proto;
    uint16_t type, flags;
    const char *name;
} cat_field;

static const cat_field k_fields[] = {
    { ETAP_FLD_IPV4_SRC,  ETAP_PROTO_IPV4, ETAP_T_IPV4,  0, "ipv4.src" },
    { ETAP_FLD_IPV4_DST,  ETAP_PROTO_IPV4, ETAP_T_IPV4,  0, "ipv4.dst" },
    { ETAP_FLD_TCP_SPORT, ETAP_PROTO_TCP,  ETAP_T_U16,   0, "tcp.sport" },
    { ETAP_FLD_TCP_DPORT, ETAP_PROTO_TCP,  ETAP_T_U16,   0, "tcp.dport" },
    { ETAP_FLD_TLS_SNI,   ETAP_PROTO_TLS,  ETAP_T_BYTES, 3, "tls.sni" },  /* optional+varlen */
    { ETAP_FLD_HTTP_HOST, ETAP_PROTO_HTTP, ETAP_T_BYTES, 3, "http.host" },
};

static const cat_field k_features[] = {
    { ETAP_FEAT_PKTS_FWD,  0, ETAP_T_U64, 0, "pkts_fwd" },
    { ETAP_FEAT_PKTS_REV,  0, ETAP_T_U64, 0, "pkts_rev" },
    { ETAP_FEAT_BYTES_FWD, 0, ETAP_T_U64, 0, "bytes_fwd" },
    { ETAP_FEAT_BYTES_REV, 0, ETAP_T_U64, 0, "bytes_rev" },
    { ETAP_FEAT_DURATION,  0, ETAP_T_DUR_NS, 0, "duration_ns" },
};

static uint32_t align8(uint32_t x) { return (x + 7u) & ~7u; }

static uint32_t fnv1a(uint32_t h, const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    if (h == 0) h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 16777619u;
    }
    return h;
}

/* ---- URI ---- */

static int parse_uri(const char *uri, uint32_t *slots)
{
    *slots = DEFAULT_SLOTS;
    if (!uri) return -1;
    if (strcmp(uri, "etap://sim") == 0) return 0;
    if (strncmp(uri, "etap://sim?", 11) != 0 &&
        strncmp(uri, "etap://local/sim", 16) != 0)
        return -1;
    const char *q = strchr(uri, '?');
    if (!q) return 0;
    q++;
    while (*q) {
        if (strncmp(q, "slots=", 6) == 0) {
            long v = strtol(q + 6, NULL, 10);
            if (v < 2) v = 2;
            if (v > MAX_SLOTS) v = MAX_SLOTS;
            *slots = (uint32_t)v;
        }
        const char *amp = strchr(q, '&');
        if (!amp) break;
        q = amp + 1;
    }
    return 0;
}

/* ---- caps ---- */

etap_status etap_open(const char *uri, const etap_open_opt *opt, etap_conn **out)
{
    (void)opt;
    uint32_t slots;
    if (parse_uri(uri, &slots) != 0) return ETAP_INVALID;
    etap_conn *c = (etap_conn *)calloc(1, sizeof(*c));
    if (!c) return ETAP_NOMEM;
    c->port_id = 1;
    c->next_sub_id = 1;
    c->slots_pref = slots;
    *out = c;
    return ETAP_OK;
}

etap_status etap_close(etap_conn *conn)
{
    if (!conn) return ETAP_INVALID;
    conn->closed = 1;
    free(conn);
    return ETAP_OK;
}

static uint32_t append_str(uint8_t *tab, uint32_t *len, uint32_t cap, const char *s)
{
    uint32_t off = *len;
    size_t n = strlen(s) + 1;
    if (off + n > cap) return 0;
    memcpy(tab + off, s, n);
    *len += (uint32_t)n;
    return off;
}

etap_status etap_discover(etap_conn *conn, etap_caps **out)
{
    if (!conn || conn->closed || !out) return ETAP_INVALID;
    const uint32_t nproto = 5, nfield = 6, nfeat = 5;
    uint8_t strtab[512];
    uint32_t slen = 0;
    uint32_t poff[5], foff[6], eoff[5], plen[5], flen[6], elen[5];
    for (uint32_t i = 0; i < nproto; i++) {
        poff[i] = append_str(strtab, &slen, sizeof(strtab), k_proto_names[i]);
        plen[i] = (uint32_t)strlen(k_proto_names[i]);
    }
    for (uint32_t i = 0; i < nfield; i++) {
        foff[i] = append_str(strtab, &slen, sizeof(strtab), k_fields[i].name);
        flen[i] = (uint32_t)strlen(k_fields[i].name);
    }
    for (uint32_t i = 0; i < nfeat; i++) {
        eoff[i] = append_str(strtab, &slen, sizeof(strtab), k_features[i].name);
        elen[i] = (uint32_t)strlen(k_features[i].name);
    }

    uint32_t off_proto = sizeof(etap_caps_hdr);
    uint32_t off_field = off_proto + nproto * (uint32_t)sizeof(etap_proto_desc);
    uint32_t off_feat  = off_field + nfield * (uint32_t)sizeof(etap_field_desc);
    uint32_t off_str   = off_feat + nfeat * (uint32_t)sizeof(etap_field_desc);
    uint32_t total     = off_str + slen;

    uint8_t *buf = (uint8_t *)calloc(1, total);
    if (!buf) return ETAP_NOMEM;

    etap_caps_hdr *h = (etap_caps_hdr *)buf;
    h->magic = ETAP_MAGIC;
    h->version = ETAP_VERSION;
    h->hdr_len = (uint16_t)sizeof(etap_caps_hdr);
    h->flags = ETAP_CAP_SHM | ETAP_CAP_SAMPLE | ETAP_CAP_AGGREGATE | ETAP_CAP_STRUCT_FLT;
    h->port_id = conn->port_id;
    h->clock = 1; /* software capture */
    h->endian = 0;
    h->max_batch_records = 4096;
    h->max_batch_bytes = 4u * 1024u * 1024u;
    h->min_wait_us = 0;
    h->max_wait_us = 1000000;
    h->max_slice = 2048;
    h->view_mask = ETAP_VIEW_PACKET | ETAP_VIEW_PARSE | ETAP_VIEW_FLOW;
    h->n_protos = (uint16_t)nproto;
    h->n_fields = (uint16_t)nfield;
    h->n_features = (uint16_t)nfeat;
    h->protos_off = off_proto;
    h->fields_off = off_field;
    h->features_off = off_feat;
    h->strtab_off = off_str;
    h->strtab_len = slen;
    h->time_res_ns = 1;
    h->snaplen_max = 2048;

    etap_proto_desc *pd = (etap_proto_desc *)(buf + off_proto);
    for (uint32_t i = 0; i < nproto; i++) {
        pd[i].proto_id = k_proto_ids[i];
        pd[i].parent_id = k_proto_parent[i];
        pd[i].name_off = poff[i];
        pd[i].name_len = (uint16_t)plen[i];
    }
    etap_field_desc *fd = (etap_field_desc *)(buf + off_field);
    for (uint32_t i = 0; i < nfield; i++) {
        fd[i].field_id = k_fields[i].id;
        fd[i].proto_id = k_fields[i].proto;
        fd[i].type = k_fields[i].type;
        fd[i].flags = k_fields[i].flags;
        fd[i].name_off = foff[i];
        fd[i].name_len = (uint16_t)flen[i];
    }
    etap_field_desc *ed = (etap_field_desc *)(buf + off_feat);
    for (uint32_t i = 0; i < nfeat; i++) {
        ed[i].field_id = k_features[i].id;
        ed[i].proto_id = k_features[i].proto;
        ed[i].type = k_features[i].type;
        ed[i].flags = k_features[i].flags;
        ed[i].name_off = eoff[i];
        ed[i].name_len = (uint16_t)elen[i];
    }
    memcpy(buf + off_str, strtab, slen);

    etap_caps *caps = (etap_caps *)calloc(1, sizeof(*caps));
    if (!caps) { free(buf); return ETAP_NOMEM; }
    caps->buf = buf;
    caps->len = total;
    *out = caps;
    return ETAP_OK;
}

void etap_caps_free(etap_caps *caps)
{
    if (!caps) return;
    free(caps->buf);
    free(caps);
}

const etap_caps_hdr *etap_caps_header(const etap_caps *caps)
{
    return caps ? (const etap_caps_hdr *)caps->buf : NULL;
}

const uint8_t *etap_caps_data(const etap_caps *caps, uint32_t *size)
{
    if (size) *size = caps ? caps->len : 0;
    return caps ? caps->buf : NULL;
}

/* ---- subscribe parse ---- */

static void default_cfg(sub_cfg *c)
{
    memset(c, 0, sizeof(*c));
    c->view_mask = ETAP_VIEW_PACKET | ETAP_VIEW_PARSE | ETAP_VIEW_FLOW;
    c->max_records = DEFAULT_MAX_RECORDS;
    c->max_bytes = DEFAULT_MAX_BYTES;
    c->packet.meta_mask = 0x0FFF;
    c->packet.bytes_mode = ETAP_BYTES_PREFIX;
    c->packet.max_bytes = 128;
    c->parse.n_fields = 6;
    for (int i = 0; i < 6; i++) c->parse.field_ids[i] = k_fields[i].id;
    c->parse.flags = 3; /* msg bounds + offsets */
    c->flow.event_mask = 0x1F;
    c->flow.flags = 1; /* pkt index */
    c->flow.n_features = 5;
    for (int i = 0; i < 5; i++) c->flow.feature_ids[i] = k_features[i].id;
}

static etap_status parse_sub_req(const etap_sub_req *req, sub_cfg *out)
{
    default_cfg(out);
    if (!req || !req->bytes || req->len < sizeof(etap_sub_req_hdr))
        return ETAP_INVALID;
    const etap_sub_req_hdr *h = (const etap_sub_req_hdr *)req->bytes;
    if (h->req_len < sizeof(*h) || h->req_len > req->len) return ETAP_INVALID;
    out->flags = h->flags;
    if (h->view_mask) out->view_mask = h->view_mask;
    if (h->max_records) out->max_records = h->max_records;
    if (h->max_bytes) out->max_bytes = h->max_bytes;
    out->max_wait_us = h->max_wait_us;
    out->budget_rps = h->budget_rps;
    out->budget_bps = h->budget_bps;
    out->overflow = h->overflow;
    out->sample_mode = h->sample_mode;
    out->sample_n = h->sample_n;
    if (out->max_records > 4096) out->max_records = 4096;
    if (out->max_bytes < 4096) out->max_bytes = 4096;
    if (out->max_bytes > 4u * 1024u * 1024u) out->max_bytes = 4u * 1024u * 1024u;

    if (h->packet_off) {
        if (h->packet_off + sizeof(etap_packet_sel_hdr) > h->req_len) return ETAP_INVALID;
        const etap_packet_sel_hdr *p =
            (const etap_packet_sel_hdr *)(req->bytes + h->packet_off);
        out->packet.meta_mask = p->meta_mask ? p->meta_mask : 0x0FFF;
        out->packet.bytes_mode = p->bytes_mode;
        out->packet.n_ranges = p->n_ranges;
        out->packet.max_bytes = p->max_bytes ? p->max_bytes : 128;
        if (p->n_ranges > MAX_RANGES) return ETAP_INVALID;
        if (p->bytes_mode == ETAP_BYTES_RANGES) {
            size_t need = sizeof(*p) + (size_t)p->n_ranges * sizeof(etap_byte_range);
            if (h->packet_off + need > h->req_len) return ETAP_INVALID;
            memcpy(out->packet.ranges, (const uint8_t *)p + sizeof(*p),
                   (size_t)p->n_ranges * sizeof(etap_byte_range));
        }
    }
    if (h->parse_off) {
        if (h->parse_off + 8 > h->req_len) return ETAP_INVALID;
        const uint8_t *p = req->bytes + h->parse_off;
        uint16_t flags, n_protos, n_fields, reserved;
        memcpy(&flags, p, 2);
        memcpy(&n_protos, p + 2, 2);
        memcpy(&n_fields, p + 4, 2);
        memcpy(&reserved, p + 6, 2);
        (void)reserved;
        if (n_fields > MAX_FIELDS || n_protos > MAX_PROTOS) return ETAP_INVALID;
        if (h->parse_off + 8u + 4u * n_protos + 4u * n_fields > h->req_len)
            return ETAP_INVALID;
        out->parse.flags = flags;
        out->parse.n_fields = n_fields;
        const uint32_t *ids = (const uint32_t *)(p + 8 + 4u * n_protos);
        for (uint16_t i = 0; i < n_fields; i++) out->parse.field_ids[i] = ids[i];
    }
    if (h->flow_off) {
        if (h->flow_off + 8 > h->req_len) return ETAP_INVALID;
        const uint8_t *p = req->bytes + h->flow_off;
        uint16_t ev, fl, nf, rs;
        memcpy(&ev, p, 2);
        memcpy(&fl, p + 2, 2);
        memcpy(&nf, p + 4, 2);
        memcpy(&rs, p + 6, 2);
        (void)rs;
        if (nf > MAX_FEATURES) return ETAP_INVALID;
        if (h->flow_off + 8u + 4u * nf > h->req_len) return ETAP_INVALID;
        out->flow.event_mask = ev ? ev : (uint16_t)0x1F;
        out->flow.flags = fl;
        out->flow.n_features = nf;
        const uint32_t *ids = (const uint32_t *)(p + 8);
        for (uint16_t i = 0; i < nf; i++) out->flow.feature_ids[i] = ids[i];
    }
    return ETAP_OK;
}

static uint32_t compute_schema_id(const sub_cfg *c)
{
    uint32_t h = 0;
    h = fnv1a(h, &c->view_mask, 4);
    h = fnv1a(h, &c->packet, sizeof(c->packet));
    h = fnv1a(h, &c->parse, sizeof(c->parse));
    h = fnv1a(h, &c->flow, sizeof(c->flow));
    if (h == 0) h = 1;
    return h;
}

static void reset_sim_flows(etap_sub *s)
{
    memset(s->flows, 0, sizeof(s->flows));
    /* 10.0.0.1:49152 -> 10.0.0.2:80 HTTP */
    s->flows[0].kind = 0;
    s->flows[0].src = 0x0a000001u;
    s->flows[0].dst = 0x0a000002u;
    s->flows[0].sport = 49152;
    s->flows[0].dport = 80;
    s->flows[0].ifindex = 1;
    /* 10.0.0.3:49153 -> 10.0.0.2:443 TLS+SNI */
    s->flows[1].kind = 1;
    s->flows[1].src = 0x0a000003u;
    s->flows[1].dst = 0x0a000002u;
    s->flows[1].sport = 49153;
    s->flows[1].dport = 443;
    s->flows[1].ifindex = 1;
    /* 10.0.0.4:49154 -> 10.0.0.2:443 TLS no SNI, later truncated */
    s->flows[2].kind = 2;
    s->flows[2].src = 0x0a000004u;
    s->flows[2].dst = 0x0a000002u;
    s->flows[2].sport = 49154;
    s->flows[2].dport = 443;
    s->flows[2].ifindex = 1;
}

static void init_sub_runtime(etap_sub *s, uint32_t n_slots, const sub_cfg *cfg)
{
    s->cfg = *cfg;
    s->n_slots = n_slots;
    s->next_batch_id = 1;
    s->seq = 0;
    s->next_pkt_id = 1;
    s->next_flow_id = 1;
    s->now_ns = SIM_T0_NS;
    s->schema_id = compute_schema_id(cfg);
    s->schema_needs_embed = 1;
    s->exhausted = 0;
    s->pkt_emitted = 0;
    reset_sim_flows(s);
    s->last_schema.schema_id = s->schema_id;
    s->last_schema.epoch = s->epoch;
}

/* ---- packet synthesis ---- */

static const char k_http[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
static const char k_sni[] = "sni.example";
/* Fake TLS-like payload with an obvious SNI marker for consistency checks. */
static const unsigned char k_tls_sni[] =
    "\x16\x03\x03\x00\x20" "SNI=sni.example";
static const unsigned char k_tls_nosni[] =
    "\x16\x03\x03\x00\x10" "APP=data";

typedef struct {
    uint64_t pkt_id, flow_id, ts_ns;
    uint32_t wire_len, cap_len, ifindex;
    uint8_t dir;
    uint16_t flags, l3_off, l4_off;
    uint8_t raw[512];
    uint32_t raw_len;
    uint32_t src, dst;
    uint16_t sport, dport;
    uint8_t kind;
    uint8_t has_sni, has_host;
    uint8_t new_flow;
    uint8_t trunc;
    sim_flow *flow;
} gen_pkt;

static void put_u16be(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put_u32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint16_t ip_checksum(const uint8_t *hdr, int len)
{
    uint32_t s = 0;
    for (int i = 0; i < len; i += 2) s += (uint32_t)((hdr[i] << 8) | hdr[i + 1]);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

static int build_frame(const sim_flow *f, unsigned pkt_in_flow, uint8_t *out, uint32_t *wire, int *trunc)
{
    const uint8_t *pay = NULL;
    uint32_t paylen = 0;
    if (f->kind == 0) {
        pay = (const uint8_t *)k_http;
        paylen = (uint32_t)strlen(k_http);
    } else if (f->kind == 1) {
        pay = k_tls_sni;
        paylen = (uint32_t)sizeof(k_tls_sni) - 1;
    } else {
        pay = k_tls_nosni;
        paylen = (uint32_t)sizeof(k_tls_nosni) - 1;
    }
    uint32_t l3 = 14, l4 = 34, body = 54;
    uint32_t full = body + paylen;
    memset(out, 0, 512);
    /* eth */
    out[0] = 0x02; out[6] = 0x02; out[7] = 0x01;
    put_u16be(out + 12, 0x0800);
    /* ipv4 */
    out[14] = 0x45;
    put_u16be(out + 16, (uint16_t)(20 + 20 + paylen));
    put_u16be(out + 18, (uint16_t)(pkt_in_flow + 1));
    out[22] = 64;
    out[23] = 6;
    put_u32be(out + 26, f->src);
    put_u32be(out + 30, f->dst);
    uint16_t csum = ip_checksum(out + 14, 20);
    put_u16be(out + 24, csum);
    /* tcp */
    put_u16be(out + 34, f->sport);
    put_u16be(out + 36, f->dport);
    put_u32be(out + 38, pkt_in_flow * 100u + 1);
    put_u32be(out + 42, 0);
    out[46] = 0x50;
    out[47] = (pkt_in_flow == 0) ? 0x02 : 0x18; /* SYN or PSH+ACK */
    put_u16be(out + 48, 65535);
    memcpy(out + 54, pay, paylen);
    *wire = full;
    *trunc = 0;
    if (f->kind == 2 && pkt_in_flow >= 2) {
        *trunc = 1;
        return 40; /* truncate inside IP/TCP headers-ish: keep 40 bytes of frame */
    }
    (void)l3; (void)l4;
    return (int)full;
}

static uint32_t flow_budget(uint8_t kind)
{
    if (kind == 0) return 8;
    if (kind == 1) return 6;
    return 4;
}

/* Pick next packet in a deterministic round-robin of the three logical flows.
 * A logical flow is reincarnated with a new flow_id after its budget. */
static int sim_next_packet(etap_sub *s, gen_pkt *gp)
{
    if (s->pkt_limit && s->pkt_emitted >= s->pkt_limit) {
        s->exhausted = 1;
        return 0;
    }
    unsigned idx = s->cycle % 3u;
    s->cycle++;
    sim_flow *f = &s->flows[idx];
    if (!f->alive) {
        f->alive = 1;
        f->flow_id = s->next_flow_id++;
        f->emitted = 0;
        f->pkts_fwd = f->pkts_rev = 0;
        f->bytes_fwd = f->bytes_rev = 0;
        f->start_ns = s->now_ns;
        f->pkt_id_first = 0;
        gp->new_flow = 1;
    } else {
        gp->new_flow = 0;
    }

    int trunc = 0;
    uint32_t wire = 0;
    int cap = build_frame(f, f->emitted, gp->raw, &wire, &trunc);
    if (cap < 0) return 0;

    gp->pkt_id = s->next_pkt_id++;
    gp->flow_id = f->flow_id;
    gp->ts_ns = s->now_ns;
    s->now_ns += PKT_IAT_NS;
    gp->wire_len = wire;
    gp->cap_len = (uint32_t)cap;
    gp->ifindex = f->ifindex;
    gp->dir = 1; /* outbound */
    gp->flags = 0;
    if (trunc) {
        gp->flags |= ETAP_RF_TRUNCATED;
        gp->trunc = 1;
    } else {
        gp->trunc = 0;
    }
    gp->l3_off = 14;
    gp->l4_off = 34;
    gp->raw_len = (uint32_t)cap;
    gp->src = f->src;
    gp->dst = f->dst;
    gp->sport = f->sport;
    gp->dport = f->dport;
    gp->kind = f->kind;
    gp->has_sni = (f->kind == 1);
    gp->has_host = (f->kind == 0);
    gp->flow = f;

    f->emitted++;
    f->pkts_fwd++;
    f->bytes_fwd += wire;
    f->last_ns = gp->ts_ns;
    if (f->pkt_id_first == 0) f->pkt_id_first = gp->pkt_id;
    f->pkt_id_last = gp->pkt_id;
    s->pkt_emitted++;
    return 1;
}

static uint32_t slice_packet(const packet_sel *sel, const gen_pkt *gp, uint8_t *dst)
{
    uint32_t maxb = sel->max_bytes ? sel->max_bytes : 128;
    switch (sel->bytes_mode) {
    case ETAP_BYTES_NONE:
        return 0;
    case ETAP_BYTES_HEADERS: {
        uint32_t n = gp->raw_len < 54 ? gp->raw_len : 54;
        if (n > maxb) n = maxb;
        memcpy(dst, gp->raw, n);
        return n;
    }
    case ETAP_BYTES_RANGES: {
        uint32_t w = 0;
        for (uint8_t i = 0; i < sel->n_ranges; i++) {
            uint32_t off = sel->ranges[i].off;
            uint32_t len = sel->ranges[i].len;
            if (off >= gp->raw_len) continue;
            if (off + len > gp->raw_len) len = gp->raw_len - off;
            if (w + len > 512) len = 512 - w;
            memcpy(dst + w, gp->raw + off, len);
            w += len;
        }
        if (w > maxb) w = maxb;
        return w;
    }
    case ETAP_BYTES_CAP:
        maxb = gp->raw_len;
        /* fall through */
    case ETAP_BYTES_PREFIX:
    default: {
        uint32_t n = gp->raw_len < maxb ? gp->raw_len : maxb;
        memcpy(dst, gp->raw, n);
        return n;
    }
    }
}

/* ---- batch encoding ---- */

typedef struct {
    uint16_t kind;
    uint32_t count;
    uint32_t off;
    uint32_t size;
} sec_tmp;

typedef struct {
    uint8_t *p;
    uint32_t cap, len;
} wbuf;

static int wb_res(wbuf *w, uint32_t n)
{
    if (w->len + n <= w->cap) return 0;
    return -1;
}

static void wb_pad8(wbuf *w)
{
    uint32_t a = align8(w->len);
    if (a > w->len && a <= w->cap) {
        memset(w->p + w->len, 0, a - w->len);
        w->len = a;
    }
}


static uint8_t has_field(const parse_sel *ps, uint32_t id)
{
    if (ps->n_fields == 0) return 1;
    for (uint16_t i = 0; i < ps->n_fields; i++)
        if (ps->field_ids[i] == id) return 1;
    return 0;
}

static uint8_t has_feat(const flow_sel *fs, uint32_t id)
{
    if (fs->n_features == 0) return 1;
    for (uint16_t i = 0; i < fs->n_features; i++)
        if (fs->feature_ids[i] == id) return 1;
    return 0;
}

static uint8_t has_meta(const packet_sel *ps, uint32_t bit)
{
    return (ps->meta_mask & bit) != 0;
}

/* Column group: n_cols u16, flags u16, n_rows u32, then 16-byte descriptors, then data. */
typedef struct {
    uint32_t col_id;
    uint16_t type;
    uint16_t flags; /* bit0 validity, bit1 varlen */
    const void *payload;
    const uint8_t *valid;
    const uint32_t *offsets; /* n_rows+1, varlen */
    uint32_t values_len;
    uint16_t width;
} col_in;

static int write_colgroup(wbuf *w, uint32_t n_rows, const col_in *cols, int n_cols)
{
    wb_pad8(w);
    uint32_t start = w->len;
    int any_valid = 0;
    for (int i = 0; i < n_cols; i++)
        if (cols[i].valid) any_valid = 1;
    uint32_t hdr = 8 + 16u * (uint32_t)n_cols;
    if (wb_res(w, hdr) != 0) return -1;
    uint8_t *base = w->p + start;
    uint16_t nc = (uint16_t)n_cols;
    uint16_t fl = any_valid ? 1 : 0;
    memcpy(base + 0, &nc, 2);
    memcpy(base + 2, &fl, 2);
    memcpy(base + 4, &n_rows, 4);
    w->len = start + hdr;

    etap_col_desc *desc = (etap_col_desc *)(base + 8);
    memset(desc, 0, 16u * (uint32_t)n_cols);

    for (int i = 0; i < n_cols; i++) {
        wb_pad8(w);
        uint32_t data_off = w->len - start;
        uint32_t data_len = 0;
        if (cols[i].valid) {
            uint32_t vlen = align8((n_rows + 7u) / 8u);
            if (wb_res(w, vlen) != 0) return -1;
            memset(w->p + w->len, 0, vlen);
            uint32_t raw = (n_rows + 7u) / 8u;
            memcpy(w->p + w->len, cols[i].valid, raw);
            w->len += vlen;
            data_len += vlen;
        }
        if (cols[i].flags & 2) {
            uint32_t offb = 4u * (n_rows + 1u);
            if (wb_res(w, offb + cols[i].values_len) != 0) return -1;
            memcpy(w->p + w->len, cols[i].offsets, offb);
            w->len += offb;
            if (cols[i].values_len) {
                memcpy(w->p + w->len, cols[i].payload, cols[i].values_len);
                w->len += cols[i].values_len;
            }
            data_len += offb + cols[i].values_len;
        } else {
            uint32_t nb = n_rows * (uint32_t)cols[i].width;
            if (wb_res(w, nb) != 0) return -1;
            if (nb) memcpy(w->p + w->len, cols[i].payload, nb);
            w->len += nb;
            data_len += nb;
        }
        desc[i].col_id = cols[i].col_id;
        desc[i].type = cols[i].type;
        desc[i].flags = cols[i].flags;
        if (cols[i].valid) desc[i].flags |= 1;
        desc[i].data_off = data_off;
        desc[i].data_len = data_len;
    }
    wb_pad8(w);
    return (int)(w->len - start);
}

static int add_section(sec_tmp *secs, int *n, uint16_t kind, uint32_t count, uint32_t off, uint32_t size)
{
    if (*n >= 16) return -1;
    secs[*n].kind = kind;
    secs[*n].count = count;
    secs[*n].off = off;
    secs[*n].size = size;
    (*n)++;
    return 0;
}

typedef struct {
    uint64_t flow_id;
    uint8_t event, state;
    uint16_t flags;
    uint32_t ifindex;
    uint64_t start_ns, last_ns, pkt_id_first, pkt_id_last;
    uint64_t pkts_fwd, pkts_rev, bytes_fwd, bytes_rev, duration_ns;
    uint32_t n_pkts_idx;
    uint32_t pkt_idx[64];
} flow_evt;

static int build_batch(etap_sub *s, uint8_t *buf, uint32_t cap, uint32_t *out_sz)
{
    const sub_cfg *cfg = &s->cfg;
    gen_pkt pkts[512];
    uint32_t n = 0;
    uint32_t want = cfg->max_records ? cfg->max_records : DEFAULT_MAX_RECORDS;
    if (want > 512) want = 512;

    while (n < want) {
        if (!sim_next_packet(s, &pkts[n])) break;
        n++;
    }
    if (n == 0) return 1; /* exhausted */

    wbuf w = { buf, cap, 0 };
    if (wb_res(&w, ETAP_BATCH_HDR_LEN) != 0) return -1;
    w.len = ETAP_BATCH_HDR_LEN;

    sec_tmp secs[16];
    int nsec = 0;
    uint32_t flags = 0;

    /* pending gaps */
    uint64_t gap_pkts = s->pending_gap_pkts;
    uint64_t gap_bytes = s->pending_gap_bytes;
    uint64_t gap_first = s->pending_gap_first;
    uint64_t gap_last = s->pending_gap_last;
    if (gap_pkts) flags |= ETAP_BF_HAS_GAP | ETAP_BF_OVERFLOW;

    int any_trunc = 0;
    for (uint32_t i = 0; i < n; i++)
        if (pkts[i].trunc) any_trunc = 1;
    if (any_trunc) flags |= ETAP_BF_TRUNCATED;

    /* PACKET_BYTES + per-row slice */
    uint8_t slices[512][512];
    uint32_t slen[512], soff[512];
    uint32_t bytes_off = 0, bytes_sz = 0;
    memset(slen, 0, sizeof(slen));
    memset(soff, 0, sizeof(soff));

    if ((cfg->view_mask & ETAP_VIEW_PACKET) &&
        cfg->packet.bytes_mode != ETAP_BYTES_NONE) {
        wb_pad8(&w);
        bytes_off = w.len;
        for (uint32_t i = 0; i < n; i++) {
            w.len = align8(w.len);
            soff[i] = w.len - bytes_off;
            slen[i] = slice_packet(&cfg->packet, &pkts[i], slices[i]);
            /* For range/prefix, cap_len in meta is captured length (platform snap),
             * bytes_len is what was copied into the batch. */
            if (wb_res(&w, slen[i]) != 0) return -1;
            if (slen[i]) memcpy(w.p + w.len, slices[i], slen[i]);
            w.len += slen[i];
        }
        wb_pad8(&w);
        bytes_sz = w.len - bytes_off;
        if (add_section(secs, &nsec, ETAP_SEC_PACKET_BYTES, n, bytes_off, bytes_sz) != 0)
            return -1;
        /* If prefix shorter than cap, mark truncated-in-delivery? Only if we cut more.
         * Platform capture truncation is already in pkt.flags. */
        for (uint32_t i = 0; i < n; i++) {
            if (slen[i] < pkts[i].cap_len && cfg->packet.bytes_mode != ETAP_BYTES_NONE)
                pkts[i].flags |= ETAP_RF_TRUNCATED;
        }
    }

    /* PACKET_META columns */
    if (cfg->view_mask & ETAP_VIEW_PACKET) {
        uint64_t col_pkt[512], col_flow[512], col_ts[512];
        uint32_t col_wire[512], col_cap[512], col_ifx[512], col_boff[512], col_blen[512];
        uint8_t col_dir[512];
        uint16_t col_fl[512], col_l3[512], col_l4[512];
        for (uint32_t i = 0; i < n; i++) {
            col_pkt[i] = pkts[i].pkt_id;
            col_flow[i] = pkts[i].flow_id;
            col_ts[i] = pkts[i].ts_ns;
            col_wire[i] = pkts[i].wire_len;
            col_cap[i] = pkts[i].cap_len;
            col_ifx[i] = pkts[i].ifindex;
            col_dir[i] = pkts[i].dir;
            col_fl[i] = pkts[i].flags;
            col_l3[i] = pkts[i].l3_off;
            col_l4[i] = pkts[i].l4_off;
            col_boff[i] = soff[i];
            col_blen[i] = slen[i];
        }
        col_in cols[16];
        int nc = 0;
        const packet_sel *ps = &cfg->packet;
#define ADD_META(bit, id, typ, ptr, wth) \
        if (has_meta(ps, bit)) { \
            cols[nc].col_id = id; cols[nc].type = typ; cols[nc].flags = 0; \
            cols[nc].payload = ptr; cols[nc].valid = NULL; cols[nc].offsets = NULL; \
            cols[nc].values_len = 0; cols[nc].width = wth; nc++; \
        }
        ADD_META(ETAP_META_PKT_ID,  ETAP_COL_PKT_ID,    ETAP_T_U64, col_pkt,  8);
        ADD_META(ETAP_META_FLOW_ID, ETAP_COL_FLOW_ID,   ETAP_T_U64, col_flow, 8);
        ADD_META(ETAP_META_TS_NS,   ETAP_COL_TS_NS,     ETAP_T_TS_NS, col_ts, 8);
        ADD_META(ETAP_META_WIRE_LEN,ETAP_COL_WIRE_LEN,  ETAP_T_U32, col_wire, 4);
        ADD_META(ETAP_META_CAP_LEN, ETAP_COL_CAP_LEN,   ETAP_T_U32, col_cap,  4);
        ADD_META(ETAP_META_DIR,     ETAP_COL_DIR,       ETAP_T_U8,  col_dir,  1);
        ADD_META(ETAP_META_IFINDEX, ETAP_COL_IFINDEX,   ETAP_T_U32, col_ifx,  4);
        ADD_META(ETAP_META_FLAGS,   ETAP_COL_FLAGS,     ETAP_T_U16, col_fl,   2);
        ADD_META(ETAP_META_L3_OFF,  ETAP_COL_L3_OFF,    ETAP_T_U16, col_l3,   2);
        ADD_META(ETAP_META_L4_OFF,  ETAP_COL_L4_OFF,    ETAP_T_U16, col_l4,   2);
        if (cfg->packet.bytes_mode != ETAP_BYTES_NONE) {
            ADD_META(0xFFFFFFFFu, ETAP_COL_BYTES_OFF, ETAP_T_U32, col_boff, 4);
            ADD_META(0xFFFFFFFFu, ETAP_COL_BYTES_LEN, ETAP_T_U32, col_blen, 4);
        }
#undef ADD_META
        /* has_meta for the last two used 0xFFFFFFFF so always true - good */

        wb_pad8(&w);
        uint32_t off = w.len;
        int sz = write_colgroup(&w, n, cols, nc);
        if (sz < 0) return -1;
        if (add_section(secs, &nsec, ETAP_SEC_PACKET_META, n, off, (uint32_t)sz) != 0)
            return -1;
    }

    /* PARSE view: one row per packet */
    uint32_t nparse = 0;
    etap_parse_index_row pi[512];
    uint32_t v_src[512], v_dst[512];
    uint16_t v_sp[512], v_dp[512];
    uint8_t  val_src[64], val_dst[64], val_sp[64], val_dp[64], val_sni[64], val_host[64];
    uint32_t sni_off[513], host_off[513];
    uint8_t  sni_heap[4096], host_heap[4096];
    uint32_t sni_len = 0, host_len = 0;
    memset(val_src, 0xff, sizeof(val_src));
    memset(val_dst, 0xff, sizeof(val_dst));
    memset(val_sp, 0xff, sizeof(val_sp));
    memset(val_dp, 0xff, sizeof(val_dp));
    memset(val_sni, 0, sizeof(val_sni));
    memset(val_host, 0, sizeof(val_host));

    if (cfg->view_mask & ETAP_VIEW_PARSE) {
        sni_off[0] = 0;
        host_off[0] = 0;
        for (uint32_t i = 0; i < n; i++) {
            etap_parse_index_row *r = &pi[nparse];
            memset(r, 0, sizeof(*r));
            r->pkt_id = pkts[i].pkt_id;
            r->msg_id = pkts[i].pkt_id; /* one message per packet in this sim */
            r->proto_id = (pkts[i].kind == 0) ? ETAP_PROTO_HTTP : ETAP_PROTO_TLS;
            r->msg_off = 54;
            if (pkts[i].cap_len > 54)
                r->msg_len = (uint16_t)(pkts[i].cap_len - 54);
            else {
                r->msg_len = 0;
                r->flags |= ETAP_RF_PARSE_INCOMPLETE;
            }
            if (pkts[i].trunc) r->flags |= ETAP_RF_TRUNCATED;
            v_src[nparse] = pkts[i].src;
            v_dst[nparse] = pkts[i].dst;
            v_sp[nparse] = pkts[i].sport;
            v_dp[nparse] = pkts[i].dport;
            if (pkts[i].has_sni) {
                val_sni[nparse / 8] = (uint8_t)(val_sni[nparse / 8] | (uint8_t)(1u << (nparse % 8)));
                uint32_t L = (uint32_t)strlen(k_sni);
                memcpy(sni_heap + sni_len, k_sni, L);
                sni_len += L;
            }
            sni_off[nparse + 1] = sni_len;
            if (pkts[i].has_host) {
                val_host[nparse / 8] = (uint8_t)(val_host[nparse / 8] | (uint8_t)(1u << (nparse % 8)));
                const char *hs = "example.com";
                uint32_t L = (uint32_t)strlen(hs);
                memcpy(host_heap + host_len, hs, L);
                host_len += L;
            }
            host_off[nparse + 1] = host_len;
            nparse++;
        }
        wb_pad8(&w);
        uint32_t ioff = w.len;
        if (wb_res(&w, nparse * (uint32_t)sizeof(etap_parse_index_row)) != 0) return -1;
        memcpy(w.p + w.len, pi, nparse * sizeof(etap_parse_index_row));
        w.len += nparse * (uint32_t)sizeof(etap_parse_index_row);
        wb_pad8(&w);
        if (add_section(secs, &nsec, ETAP_SEC_PARSE_INDEX, nparse, ioff,
                        w.len - ioff) != 0)
            return -1;

        col_in cols[16];
        int nc = 0;
        const parse_sel *ps = &cfg->parse;
        if (has_field(ps, ETAP_FLD_IPV4_SRC)) {
            cols[nc++] = (col_in){ ETAP_FLD_IPV4_SRC, ETAP_T_IPV4, 0, v_src, val_src, NULL, 0, 4 };
        }
        if (has_field(ps, ETAP_FLD_IPV4_DST)) {
            cols[nc++] = (col_in){ ETAP_FLD_IPV4_DST, ETAP_T_IPV4, 0, v_dst, val_dst, NULL, 0, 4 };
        }
        if (has_field(ps, ETAP_FLD_TCP_SPORT)) {
            cols[nc++] = (col_in){ ETAP_FLD_TCP_SPORT, ETAP_T_U16, 0, v_sp, val_sp, NULL, 0, 2 };
        }
        if (has_field(ps, ETAP_FLD_TCP_DPORT)) {
            cols[nc++] = (col_in){ ETAP_FLD_TCP_DPORT, ETAP_T_U16, 0, v_dp, val_dp, NULL, 0, 2 };
        }
        if (has_field(ps, ETAP_FLD_TLS_SNI)) {
            cols[nc++] = (col_in){ ETAP_FLD_TLS_SNI, ETAP_T_BYTES, 3, sni_heap, val_sni, sni_off, sni_len, 0 };
        }
        if (has_field(ps, ETAP_FLD_HTTP_HOST)) {
            cols[nc++] = (col_in){ ETAP_FLD_HTTP_HOST, ETAP_T_BYTES, 3, host_heap, val_host, host_off, host_len, 0 };
        }
        if (nc > 0) {
            wb_pad8(&w);
            uint32_t off = w.len;
            int sz = write_colgroup(&w, nparse, cols, nc);
            if (sz < 0) return -1;
            if (add_section(secs, &nsec, ETAP_SEC_PARSE_COLS, nparse, off, (uint32_t)sz) != 0)
                return -1;
        }
    }

    /* FLOW view: emit New on first packet of a flow in this batch, else Update.
     * Expire is not emitted in the pull generator (flows reincarnate after budget
     * — we emit Expire then New when a logical flow wraps). */
    flow_evt evs[16];
    uint32_t ne = 0;
    if (cfg->view_mask & ETAP_VIEW_FLOW) {
        for (uint32_t i = 0; i < n; i++) {
            uint64_t fid = pkts[i].flow_id;
            int found = -1;
            for (uint32_t k = 0; k < ne; k++)
                if (evs[k].flow_id == fid) { found = (int)k; break; }
            if (found < 0) {
                if (ne >= 16) break;
                found = (int)ne++;
                memset(&evs[found], 0, sizeof(evs[found]));
                evs[found].flow_id = fid;
                evs[found].event = pkts[i].new_flow ? 1 : 2; /* New / Update */
                evs[found].state = 2;
                evs[found].ifindex = pkts[i].ifindex;
                evs[found].start_ns = pkts[i].flow->start_ns;
                evs[found].pkt_id_first = pkts[i].flow->pkt_id_first;
            }
            evs[found].last_ns = pkts[i].ts_ns;
            evs[found].pkt_id_last = pkts[i].pkt_id;
            evs[found].pkts_fwd = pkts[i].flow->pkts_fwd;
            evs[found].pkts_rev = pkts[i].flow->pkts_rev;
            evs[found].bytes_fwd = pkts[i].flow->bytes_fwd;
            evs[found].bytes_rev = pkts[i].flow->bytes_rev;
            evs[found].duration_ns = evs[found].last_ns - evs[found].start_ns;
            if (evs[found].n_pkts_idx < 64)
                evs[found].pkt_idx[evs[found].n_pkts_idx++] = i;
        }
        /* If a flow just hit its budget, mark it dead so the next packet reincarnates.
         * Emit Expire only when the wrapping packet is *not* in this batch; the
         * current batch already has the last packets as Update/New. */
        for (int fi = 0; fi < 3; fi++) {
            sim_flow *f = &s->flows[fi];
            if (f->alive && f->emitted >= flow_budget(f->kind))
                f->alive = 0;
        }

        etap_flow_meta_row fr[16];
        memset(fr, 0, sizeof(fr));
        uint64_t ffwd[16], frev[16], bfwd[16], brev[16], dur[16];
        for (uint32_t i = 0; i < ne; i++) {
            fr[i].flow_id = evs[i].flow_id;
            fr[i].event = evs[i].event;
            fr[i].state = evs[i].state;
            fr[i].flags = evs[i].flags;
            fr[i].ifindex = evs[i].ifindex;
            fr[i].start_ns = evs[i].start_ns;
            fr[i].last_ns = evs[i].last_ns;
            fr[i].pkt_id_first = evs[i].pkt_id_first;
            fr[i].pkt_id_last = evs[i].pkt_id_last;
            ffwd[i] = evs[i].pkts_fwd;
            frev[i] = evs[i].pkts_rev;
            bfwd[i] = evs[i].bytes_fwd;
            brev[i] = evs[i].bytes_rev;
            dur[i] = evs[i].duration_ns;
        }
        wb_pad8(&w);
        uint32_t moff = w.len;
        if (wb_res(&w, ne * (uint32_t)sizeof(etap_flow_meta_row)) != 0) return -1;
        memcpy(w.p + w.len, fr, ne * sizeof(etap_flow_meta_row));
        w.len += ne * (uint32_t)sizeof(etap_flow_meta_row);
        wb_pad8(&w);
        if (add_section(secs, &nsec, ETAP_SEC_FLOW_META, ne, moff, w.len - moff) != 0)
            return -1;

        col_in cols[8];
        int nc = 0;
        const flow_sel *fs = &cfg->flow;
        if (has_feat(fs, ETAP_FEAT_PKTS_FWD))
            cols[nc++] = (col_in){ ETAP_FEAT_PKTS_FWD, ETAP_T_U64, 0, ffwd, NULL, NULL, 0, 8 };
        if (has_feat(fs, ETAP_FEAT_PKTS_REV))
            cols[nc++] = (col_in){ ETAP_FEAT_PKTS_REV, ETAP_T_U64, 0, frev, NULL, NULL, 0, 8 };
        if (has_feat(fs, ETAP_FEAT_BYTES_FWD))
            cols[nc++] = (col_in){ ETAP_FEAT_BYTES_FWD, ETAP_T_U64, 0, bfwd, NULL, NULL, 0, 8 };
        if (has_feat(fs, ETAP_FEAT_BYTES_REV))
            cols[nc++] = (col_in){ ETAP_FEAT_BYTES_REV, ETAP_T_U64, 0, brev, NULL, NULL, 0, 8 };
        if (has_feat(fs, ETAP_FEAT_DURATION))
            cols[nc++] = (col_in){ ETAP_FEAT_DURATION, ETAP_T_DUR_NS, 0, dur, NULL, NULL, 0, 8 };
        if (nc) {
            wb_pad8(&w);
            uint32_t off = w.len;
            int sz = write_colgroup(&w, ne, cols, nc);
            if (sz < 0) return -1;
            if (add_section(secs, &nsec, ETAP_SEC_FLOW_FEAT, ne, off, (uint32_t)sz) != 0)
                return -1;
        }
        if (cfg->flow.flags & 1) {
            /* FLOW_PKTS: offsets + pkt_id list */
            uint32_t offs[17];
            uint64_t ids[16 * 64];
            uint32_t nids = 0;
            offs[0] = 0;
            for (uint32_t i = 0; i < ne; i++) {
                for (uint32_t k = 0; k < evs[i].n_pkts_idx; k++) {
                    uint32_t pi_ = evs[i].pkt_idx[k];
                    ids[nids++] = pkts[pi_].pkt_id;
                }
                offs[i + 1] = nids * 8u; /* byte offsets into values? Spec: varlen col of pkt_id */
            }
            /* Use byte offsets into the u64 values blob. */
            /* Recompute byte offsets */
            uint32_t cursor = 0;
            uint32_t boffs[17];
            boffs[0] = 0;
            uint32_t ti = 0;
            for (uint32_t i = 0; i < ne; i++) {
                cursor += evs[i].n_pkts_idx * 8u;
                boffs[i + 1] = cursor;
                ti += evs[i].n_pkts_idx;
            }
            (void)offs; (void)ti;
            wb_pad8(&w);
            uint32_t off = w.len;
            col_in pcol = { 1, ETAP_T_U64, 2, ids, NULL, boffs, nids * 8u, 8 };
            int sz = write_colgroup(&w, ne, &pcol, 1);
            if (sz < 0) return -1;
            if (add_section(secs, &nsec, ETAP_SEC_FLOW_PKTS, ne, off, (uint32_t)sz) != 0)
                return -1;
        }
    }

    if (s->schema_needs_embed) {
        flags |= ETAP_BF_SCHEMA_EMBEDDED;
        wb_pad8(&w);
        uint32_t off = w.len;
        uint32_t payload[4] = { s->schema_id, s->epoch, cfg->view_mask, cfg->packet.meta_mask };
        if (wb_res(&w, sizeof(payload)) != 0) return -1;
        memcpy(w.p + w.len, payload, sizeof(payload));
        w.len += sizeof(payload);
        wb_pad8(&w);
        if (add_section(secs, &nsec, ETAP_SEC_SCHEMA, 1, off, w.len - off) != 0)
            return -1;
        s->schema_needs_embed = 0;
    }

    /* section directory */
    wb_pad8(&w);
    uint32_t sec_off = w.len;
    if (wb_res(&w, (uint32_t)nsec * sizeof(etap_section)) != 0) return -1;
    for (int i = 0; i < nsec; i++) {
        etap_section sc;
        memset(&sc, 0, sizeof(sc));
        sc.kind = secs[i].kind;
        sc.count = secs[i].count;
        sc.off = secs[i].off;
        sc.size = secs[i].size;
        memcpy(w.p + w.len, &sc, sizeof(sc));
        w.len += (uint32_t)sizeof(sc);
    }
    uint32_t total = w.len;

    etap_batch_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = ETAP_MAGIC;
    hdr.version = ETAP_VERSION;
    hdr.hdr_len = ETAP_BATCH_HDR_LEN;
    hdr.flags = flags;
    hdr.n_sections = (uint16_t)nsec;
    hdr.clock = 1;
    hdr.batch_id = s->next_batch_id++;
    hdr.sub_id = s->sub_id;
    hdr.epoch = s->epoch;
    hdr.schema_id = s->schema_id;
    hdr.seq = s->seq++;
    hdr.time_first_ns = pkts[0].ts_ns;
    hdr.time_last_ns = pkts[n - 1].ts_ns;
    hdr.n_packets = (cfg->view_mask & ETAP_VIEW_PACKET) ? n : 0;
    hdr.n_parse_rows = (cfg->view_mask & ETAP_VIEW_PARSE) ? nparse : 0;
    hdr.n_flows = (cfg->view_mask & ETAP_VIEW_FLOW) ? ne : 0;
    hdr.gap_dropped_pkts = gap_pkts;
    hdr.gap_dropped_bytes = gap_bytes;
    hdr.gap_first_pkt_id = gap_first;
    hdr.gap_last_pkt_id = gap_last;
    hdr.producer_lag_us = 0;
    hdr.crc32c = 0;
    hdr.sections_off = sec_off;
    hdr.total_size = total;
    memcpy(buf, &hdr, sizeof(hdr));

    if (gap_pkts) {
        s->pending_gap_pkts = 0;
        s->pending_gap_bytes = 0;
        s->pending_gap_first = 0;
        s->pending_gap_last = 0;
    }
    s->delivered_batches++;
    s->delivered_pkts += n;
    *out_sz = total;
    return 0;
}

/* ---- slot helpers ---- */

static int find_slot(etap_sub *s, int state)
{
    for (uint32_t i = 0; i < s->n_slots; i++)
        if (s->slots[i].state == state) return (int)i;
    return -1;
}

static etap_status enqueue_built(etap_sub *s, uint8_t *tmp, uint32_t sz)
{
    int si = find_slot(s, SLOT_EMPTY);
    if (si < 0) return ETAP_NOMEM;
    slot *sl = &s->slots[si];
    if (sl->cap < sz) {
        uint8_t *nb = (uint8_t *)realloc(sl->buf, sz);
        if (!nb) return ETAP_NOMEM;
        sl->buf = nb;
        sl->cap = sz;
    }
    memcpy(sl->buf, tmp, sz);
    sl->size = sz;
    sl->batch_id = ((etap_batch_hdr *)tmp)->batch_id;
    sl->state = SLOT_READY;
    return ETAP_OK;
}

static etap_status produce_one(etap_sub *s, int into_ready)
{
    uint32_t cap = s->cfg.max_bytes + 8192;
    if (cap < 65536) cap = 65536;
    uint8_t *tmp = (uint8_t *)malloc(cap);
    if (!tmp) return ETAP_NOMEM;
    uint32_t sz = 0;
    int rc = build_batch(s, tmp, cap, &sz);
    if (rc != 0) {
        free(tmp);
        return rc > 0 ? ETAP_EMPTY : ETAP_NOMEM;
    }
    if (into_ready) {
        etap_status st = enqueue_built(s, tmp, sz);
        free(tmp);
        return st;
    }
    /* unused path */
    free(tmp);
    return ETAP_OK;
}

static etap_batch *lease_slot(etap_sub *s, int si)
{
    slot *sl = &s->slots[si];
    sl->state = SLOT_LEASED;
    etap_batch *b = (etap_batch *)calloc(1, sizeof(*b));
    if (!b) {
        sl->state = SLOT_READY;
        return NULL;
    }
    b->sub = s;
    b->slot_index = si;
    b->buf = sl->buf;
    b->size = sl->size;
    b->schema.schema_id = s->schema_id;
    b->schema.epoch = s->epoch;
    s->leased_batches++;
    return b;
}

etap_status etap_subscribe(etap_conn *conn, const etap_sub_req *req, etap_sub **out)
{
    if (!conn || conn->closed || !out) return ETAP_INVALID;
    sub_cfg cfg;
    etap_status st = parse_sub_req(req, &cfg);
    if (st != ETAP_OK) return st;
    etap_sub *s = (etap_sub *)calloc(1, sizeof(*s));
    if (!s) return ETAP_NOMEM;
    if (pthread_mutex_init(&s->mu, NULL) != 0) { free(s); return ETAP_NOMEM; }
    s->conn = conn;
    s->sub_id = conn->next_sub_id++;
    s->epoch = 1;
    init_sub_runtime(s, conn->slots_pref, &cfg);
    *out = s;
    return ETAP_OK;
}

etap_status etap_resubscribe(etap_sub *sub, const etap_sub_req *req)
{
    if (!sub || sub->closed) return ETAP_CLOSED;
    sub_cfg cfg;
    etap_status st = parse_sub_req(req, &cfg);
    if (st != ETAP_OK) return st;
    pthread_mutex_lock(&sub->mu);
    uint32_t new_schema = compute_schema_id(&cfg);
    int destructive = (cfg.flags & 1u) != 0;
    /* Drop queued but unleased batches; leased ones stay until release. */
    for (uint32_t i = 0; i < sub->n_slots; i++) {
        if (sub->slots[i].state == SLOT_READY)
            sub->slots[i].state = SLOT_EMPTY;
    }
    sub->cfg = cfg;
    sub->schema_id = new_schema;
    sub->schema_needs_embed = 1;
    if (destructive) {
        sub->epoch++;
        sub->next_pkt_id = 1;
        sub->next_flow_id = 1;
        sub->now_ns = SIM_T0_NS;
        sub->cycle = 0;
        sub->pkt_emitted = 0;
        sub->exhausted = 0;
        reset_sim_flows(sub);
    }
    sub->last_schema.schema_id = sub->schema_id;
    sub->last_schema.epoch = sub->epoch;
    pthread_mutex_unlock(&sub->mu);
    return ETAP_OK;
}

static void free_sub_locked(etap_sub *s)
{
    for (uint32_t i = 0; i < s->n_slots; i++)
        free(s->slots[i].buf);
    pthread_mutex_unlock(&s->mu);
    pthread_mutex_destroy(&s->mu);
    free(s);
}

etap_status etap_unsubscribe(etap_sub *sub)
{
    if (!sub) return ETAP_INVALID;
    pthread_mutex_lock(&sub->mu);
    sub->closed = 1;
    free_sub_locked(sub);
    return ETAP_OK;
}

etap_status etap_poll(etap_sub *sub, uint32_t timeout_us, etap_batch **out)
{
    (void)timeout_us;
    if (!sub || !out) return ETAP_INVALID;
    *out = NULL;
    pthread_mutex_lock(&sub->mu);
    if (sub->closed) { pthread_mutex_unlock(&sub->mu); return ETAP_CLOSED; }
    int si = find_slot(sub, SLOT_READY);
    if (si >= 0) {
        etap_batch *b = lease_slot(sub, si);
        pthread_mutex_unlock(&sub->mu);
        if (!b) return ETAP_NOMEM;
        *out = b;
        return ETAP_OK;
    }
    /* Pull one batch into a new slot, then lease it. */
    int empty = find_slot(sub, SLOT_EMPTY);
    if (empty < 0) {
        pthread_mutex_unlock(&sub->mu);
        return ETAP_EMPTY;
    }
    etap_status st = produce_one(sub, 1);
    if (st != ETAP_OK) {
        pthread_mutex_unlock(&sub->mu);
        return st;
    }
    si = find_slot(sub, SLOT_READY);
    if (si < 0) {
        pthread_mutex_unlock(&sub->mu);
        return ETAP_EMPTY;
    }
    etap_batch *b = lease_slot(sub, si);
    pthread_mutex_unlock(&sub->mu);
    if (!b) return ETAP_NOMEM;
    *out = b;
    return ETAP_OK;
}

etap_status etap_release(etap_batch *batch)
{
    if (!batch) return ETAP_INVALID;
    etap_sub *s = batch->sub;
    pthread_mutex_lock(&s->mu);
    int si = batch->slot_index;
    if (si >= 0 && (uint32_t)si < s->n_slots && s->slots[si].state == SLOT_LEASED) {
        s->slots[si].state = SLOT_EMPTY;
        if (s->leased_batches) s->leased_batches--;
    }
    pthread_mutex_unlock(&s->mu);
    free(batch);
    return ETAP_OK;
}

const etap_batch_hdr *etap_batch_header(const etap_batch *batch)
{
    return batch ? (const etap_batch_hdr *)batch->buf : NULL;
}

const etap_schema *etap_batch_schema(const etap_batch *batch)
{
    return batch ? &batch->schema : NULL;
}

const uint8_t *etap_batch_data(const etap_batch *batch, uint32_t *size)
{
    if (size) *size = batch ? batch->size : 0;
    return batch ? batch->buf : NULL;
}

static const etap_section *sections_of(const etap_batch *b, uint16_t *n)
{
    const etap_batch_hdr *h = etap_batch_header(b);
    if (!h) return NULL;
    if (n) *n = h->n_sections;
    return (const etap_section *)(b->buf + h->sections_off);
}

static const etap_section *find_sec(const etap_batch *b, uint16_t kind)
{
    uint16_t n = 0;
    const etap_section *s = sections_of(b, &n);
    if (!s) return NULL;
    for (uint16_t i = 0; i < n; i++)
        if (s[i].kind == kind) return &s[i];
    return NULL;
}

const etap_parse_index_row *etap_parse_index(const etap_batch *batch, uint32_t *n)
{
    const etap_section *s = find_sec(batch, ETAP_SEC_PARSE_INDEX);
    if (n) *n = s ? s->count : 0;
    if (!s) return NULL;
    return (const etap_parse_index_row *)(batch->buf + s->off);
}

const etap_flow_meta_row *etap_flow_meta(const etap_batch *batch, uint32_t *n)
{
    const etap_section *s = find_sec(batch, ETAP_SEC_FLOW_META);
    if (n) *n = s ? s->count : 0;
    if (!s) return NULL;
    return (const etap_flow_meta_row *)(batch->buf + s->off);
}

etap_status etap_col(const etap_batch *batch, uint16_t section_kind, uint32_t col_id,
                     etap_type *type, uint32_t *n,
                     const void **data, const uint8_t **valid,
                     const uint32_t **offsets)
{
    if (type) *type = (etap_type)0;
    if (n) *n = 0;
    if (data) *data = NULL;
    if (valid) *valid = NULL;
    if (offsets) *offsets = NULL;
    const etap_section *s = find_sec(batch, section_kind);
    if (!s || s->size < 8) return ETAP_SCHEMA;
    const uint8_t *base = batch->buf + s->off;
    uint16_t n_cols, flags;
    uint32_t n_rows;
    memcpy(&n_cols, base + 0, 2);
    memcpy(&flags, base + 2, 2);
    memcpy(&n_rows, base + 4, 4);
    if (8u + 16u * n_cols > s->size) return ETAP_SCHEMA;
    const etap_col_desc *d = (const etap_col_desc *)(base + 8);
    const etap_col_desc *hit = NULL;
    for (uint16_t i = 0; i < n_cols; i++)
        if (d[i].col_id == col_id) { hit = &d[i]; break; }
    if (!hit) return ETAP_INVALID;
    if (type) *type = (etap_type)hit->type;
    if (n) *n = n_rows;
    const uint8_t *dp = base + hit->data_off;
    uint32_t remain = hit->data_len;
    if (hit->flags & 1) {
        uint32_t vlen = align8((n_rows + 7u) / 8u);
        if (remain < vlen) return ETAP_SCHEMA;
        if (valid) *valid = dp;
        dp += vlen;
        remain -= vlen;
    }
    if (hit->flags & 2) {
        uint32_t offb = 4u * (n_rows + 1u);
        if (remain < offb) return ETAP_SCHEMA;
        if (offsets) *offsets = (const uint32_t *)dp;
        dp += offb;
        remain -= offb;
        if (data) *data = dp;
    } else {
        if (data) *data = dp;
    }
    (void)flags;
    return ETAP_OK;
}

etap_span etap_packet_bytes(const etap_batch *batch, uint32_t index)
{
    etap_span sp = { NULL, 0 };
    const etap_section *bytes = find_sec(batch, ETAP_SEC_PACKET_BYTES);
    if (!bytes) return sp;
    etap_type t;
    uint32_t n = 0;
    const void *offp = NULL, *lenp = NULL;
    if (etap_col(batch, ETAP_SEC_PACKET_META, ETAP_COL_BYTES_OFF, &t, &n, &offp, NULL, NULL) != ETAP_OK)
        return sp;
    if (etap_col(batch, ETAP_SEC_PACKET_META, ETAP_COL_BYTES_LEN, &t, &n, &lenp, NULL, NULL) != ETAP_OK)
        return sp;
    if (index >= n) return sp;
    uint32_t off = ((const uint32_t *)offp)[index];
    uint32_t len = ((const uint32_t *)lenp)[index];
    if (off + len > bytes->size) return sp;
    sp.data = batch->buf + bytes->off + off;
    sp.len = len;
    return sp;
}

etap_status etap_stats(etap_sub *sub, etap_sub_stats *out)
{
    if (!sub || !out) return ETAP_INVALID;
    pthread_mutex_lock(&sub->mu);
    memset(out, 0, sizeof(*out));
    out->delivered_batches = sub->delivered_batches;
    out->delivered_pkts = sub->delivered_pkts;
    out->dropped_pkts = sub->dropped_pkts;
    out->dropped_bytes = sub->dropped_bytes;
    out->leased_batches = sub->leased_batches;
    uint32_t depth = 0;
    for (uint32_t i = 0; i < sub->n_slots; i++)
        if (sub->slots[i].state == SLOT_READY) depth++;
    out->queue_depth = depth;
    out->lag_us = 0;
    out->epoch = sub->epoch;
    out->schema_id = sub->schema_id;
    pthread_mutex_unlock(&sub->mu);
    return ETAP_OK;
}

etap_status etap_sim_fill_ring(etap_sub *sub, uint32_t *queued)
{
    if (!sub) return ETAP_INVALID;
    if (queued) *queued = 0;
    pthread_mutex_lock(&sub->mu);
    uint32_t n = 0;
    for (;;) {
        if (find_slot(sub, SLOT_EMPTY) < 0) break;
        etap_status st = produce_one(sub, 1);
        if (st != ETAP_OK) break;
        n++;
    }
    pthread_mutex_unlock(&sub->mu);
    if (queued) *queued = n;
    return ETAP_OK;
}

etap_status etap_sim_drop(etap_sub *sub, uint64_t n_pkts, uint64_t n_bytes)
{
    if (!sub) return ETAP_INVALID;
    pthread_mutex_lock(&sub->mu);
    if (n_pkts) {
        uint64_t first = sub->next_pkt_id;
        sub->pending_gap_pkts += n_pkts;
        sub->pending_gap_bytes += n_bytes;
        if (sub->pending_gap_first == 0) sub->pending_gap_first = first;
        sub->next_pkt_id += n_pkts;
        sub->pending_gap_last = sub->next_pkt_id - 1;
        sub->dropped_pkts += n_pkts;
        sub->dropped_bytes += n_bytes;
    }
    pthread_mutex_unlock(&sub->mu);
    return ETAP_OK;
}

etap_status etap_sim_set_limit(etap_sub *sub, uint32_t remaining_pkts)
{
    if (!sub) return ETAP_INVALID;
    pthread_mutex_lock(&sub->mu);
    sub->pkt_limit = sub->pkt_emitted + remaining_pkts;
    if (remaining_pkts == 0) sub->exhausted = 1;
    pthread_mutex_unlock(&sub->mu);
    return ETAP_OK;
}
