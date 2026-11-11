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

typedef struct {
    uint16_t section_kind;
    uint32_t col_id;
    etap_type type;
    uint32_t n;
    uint8_t *data;      /* native-width array or varlen heap (owned or alias) */
    uint8_t *valid;     /* may alias the raw buffer */
    uint32_t *offsets;  /* varlen; may alias the raw buffer */
    int owned;          /* data/valid/offsets allocated by the cache */
} col_cache_ent;

struct etap_batch {
    struct etap_sub *sub;
    int slot_index;
    uint8_t *buf;
    uint32_t size;
    struct etap_schema schema;
    etap_batch_hdr hdr; /* decoded; always includes gap fields */
    int hdr_ok;
    col_cache_ent *cache;
    uint32_t n_cache, cap_cache;
    etap_parse_index_row *parse_rows;
    uint32_t n_parse_rows;
    int parse_ready;
    etap_flow_meta_row *flow_rows;
    uint32_t n_flow_rows;
    int flow_ready;
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

static uint32_t align4(uint32_t x) { return (x + 3u) & ~3u; }

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

static void wb_pad4(wbuf *w)
{
    uint32_t a = align4(w->len);
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

static uint32_t type_width(uint8_t t)
{
    switch (t) {
    case ETAP_T_U8: case ETAP_T_I8: case ETAP_T_BOOL: return 1;
    case ETAP_T_U16: case ETAP_T_I16: return 2;
    case ETAP_T_U32: case ETAP_T_I32: case ETAP_T_F32:
    case ETAP_T_IPV4: case ETAP_T_ENUM: return 4;
    case ETAP_T_U64: case ETAP_T_I64: case ETAP_T_F64:
    case ETAP_T_TS_NS: case ETAP_T_DUR_NS: return 8;
    case ETAP_T_MAC: return 6;
    case ETAP_T_IPV6: return 16;
    default: return 0;
    }
}

static int is_int_like(uint8_t t)
{
    switch (t) {
    case ETAP_T_U8: case ETAP_T_U16: case ETAP_T_U32: case ETAP_T_U64:
    case ETAP_T_I8: case ETAP_T_I16: case ETAP_T_I32: case ETAP_T_I64:
    case ETAP_T_BOOL: case ETAP_T_ENUM: case ETAP_T_IPV4:
    case ETAP_T_TS_NS: case ETAP_T_DUR_NS:
        return 1;
    default:
        return 0;
    }
}

static int is_signed_type(uint8_t t)
{
    return t == ETAP_T_I8 || t == ETAP_T_I16 || t == ETAP_T_I32 || t == ETAP_T_I64;
}

static int try_delta_type(uint8_t typ)
{
    return typ == ETAP_T_U64 || typ == ETAP_T_TS_NS || typ == ETAP_T_DUR_NS || typ == ETAP_T_U32;
}

static uint8_t bits_for(uint32_t maxv)
{
    uint8_t b = 0;
    do {
        b++;
        maxv >>= 1;
    } while (maxv);
    return b;
}

static uint32_t packed_words(uint32_t n, uint8_t bw)
{
    return (n * (uint32_t)bw + 31u) / 32u;
}

static uint64_t load_u(const uint8_t *row, uint32_t width)
{
    uint64_t v = 0;
    memcpy(&v, row, width);
    return v;
}

static int64_t load_s(const uint8_t *row, uint32_t width)
{
    uint64_t u = load_u(row, width);
    if (width < 8 && (u & (1ull << (8u * width - 1u))))
        u |= ~((1ull << (8u * width)) - 1ull);
    return (int64_t)u;
}

static void store_u(uint8_t *row, uint32_t width, uint64_t v)
{
    memcpy(row, &v, width);
}

static uint64_t zigzag64(int64_t d)
{
    return ((uint64_t)d << 1) ^ (uint64_t)(d >> 63);
}

static int64_t unzigzag64(uint64_t z)
{
    return (int64_t)((z >> 1) ^ (uint64_t)-(int64_t)(z & 1));
}

static void pack_u32_bits(uint8_t *dst, const uint32_t *src, uint32_t n, uint8_t bw)
{
    uint32_t nw = packed_words(n, bw);
    memset(dst, 0, (size_t)nw * 4u);
    uint64_t acc = 0;
    int acc_bits = 0;
    uint32_t wo = 0;
    uint32_t mask = (bw == 32) ? 0xFFFFFFFFu : ((1u << bw) - 1u);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t v = src[i] & mask;
        acc |= ((uint64_t)v) << acc_bits;
        acc_bits += bw;
        while (acc_bits >= 32) {
            uint32_t word = (uint32_t)acc;
            memcpy(dst + wo * 4u, &word, 4);
            wo++;
            acc >>= 32;
            acc_bits -= 32;
        }
    }
    if (acc_bits > 0) {
        uint32_t word = (uint32_t)acc;
        memcpy(dst + wo * 4u, &word, 4);
    }
}

static void unpack_u32_bits(uint32_t *dst, const uint8_t *src, uint32_t n, uint8_t bw)
{
    uint32_t mask = (bw == 32) ? 0xFFFFFFFFu : ((1u << bw) - 1u);
    uint64_t acc = 0;
    int acc_bits = 0;
    uint32_t wo = 0;
    uint32_t nw = packed_words(n, bw);
    for (uint32_t i = 0; i < n; i++) {
        while (acc_bits < bw) {
            uint32_t word = 0;
            if (wo < nw) memcpy(&word, src + wo * 4u, 4);
            acc |= ((uint64_t)word) << acc_bits;
            acc_bits += 32;
            wo++;
        }
        dst[i] = (uint32_t)acc & mask;
        acc >>= bw;
        acc_bits -= bw;
    }
}

static int all_equal_rows(const uint8_t *vals, uint32_t n, uint32_t width)
{
    if (n <= 1) return 1;
    for (uint32_t i = 1; i < n; i++)
        if (memcmp(vals + (size_t)i * width, vals, width) != 0) return 0;
    return 1;
}

/* Encode a fixed-width column. *out is malloc'd when *out_len > 0 (and may be
 * malloc'd even when len==0 — caller always frees). */
static int encode_fixed(const void *payload, uint32_t n, uint8_t typ,
                        uint8_t *codec, uint8_t *bit_width,
                        uint8_t **out, uint32_t *out_len)
{
    uint32_t width = type_width(typ);
    const uint8_t *vals = (const uint8_t *)payload;
    *codec = ETAP_CODEC_RAW;
    *bit_width = 0;
    *out = NULL;
    *out_len = 0;

    if (n == 0 || width == 0)
        return 0;

    uint32_t raw_sz = n * width;

    if (all_equal_rows(vals, n, width)) {
        *out = (uint8_t *)malloc(width);
        if (!*out) return -1;
        memcpy(*out, vals, width);
        *out_len = width;
        *codec = ETAP_CODEC_CONST;
        return 0;
    }

    uint8_t *best = (uint8_t *)malloc(raw_sz);
    if (!best) return -1;
    memcpy(best, vals, raw_sz);
    uint32_t best_len = raw_sz;
    uint8_t best_codec = ETAP_CODEC_RAW;
    uint8_t best_bw = 0;

    if (!is_int_like(typ)) {
        *out = best;
        *out_len = best_len;
        return 0;
    }

    int signed_t = is_signed_type(typ);

    if (try_delta_type(typ) && n >= 2) {
        int ok = 1;
        uint32_t nd = n - 1;
        uint32_t *dz = (uint32_t *)malloc(nd * 4u);
        if (!dz) { free(best); return -1; }
        uint32_t maxz = 0;
        for (uint32_t i = 1; i < n; i++) {
            uint64_t a = load_u(vals + (i - 1) * width, width);
            uint64_t b = load_u(vals + i * width, width);
            int64_t dlt = (int64_t)b - (int64_t)a;
            uint64_t z = zigzag64(dlt);
            if (z > 0xFFFFFFFFull) { ok = 0; break; }
            dz[i - 1] = (uint32_t)z;
            if (dz[i - 1] > maxz) maxz = dz[i - 1];
        }
        if (ok) {
            uint8_t bw = bits_for(maxz);
            uint32_t tlen = width + packed_words(nd, bw) * 4u;
            if (tlen < best_len) {
                uint8_t *buf = (uint8_t *)malloc(tlen);
                if (!buf) { free(dz); free(best); return -1; }
                memcpy(buf, vals, width);
                pack_u32_bits(buf + width, dz, nd, bw);
                free(best);
                best = buf;
                best_len = tlen;
                best_codec = ETAP_CODEC_DELTA;
                best_bw = bw;
            }
        }
        free(dz);
    }

    {
        int ok = 1;
        uint64_t base_u = 0, range = 0;
        if (signed_t) {
            int64_t minv = load_s(vals, width);
            int64_t maxv = minv;
            for (uint32_t i = 1; i < n; i++) {
                int64_t v = load_s(vals + i * width, width);
                if (v < minv) minv = v;
                if (v > maxv) maxv = v;
            }
            if ((uint64_t)(maxv - minv) > 0xFFFFFFFFull) ok = 0;
            else {
                range = (uint64_t)(maxv - minv);
                base_u = (uint64_t)minv;
            }
        } else {
            uint64_t umin = load_u(vals, width);
            uint64_t umax = umin;
            for (uint32_t i = 1; i < n; i++) {
                uint64_t v = load_u(vals + i * width, width);
                if (v < umin) umin = v;
                if (v > umax) umax = v;
            }
            if (umax - umin > 0xFFFFFFFFull) ok = 0;
            else {
                range = umax - umin;
                base_u = umin;
            }
        }
        if (ok) {
            uint8_t bw = bits_for((uint32_t)range);
            uint32_t tlen = width + packed_words(n, bw) * 4u;
            if (tlen < best_len) {
                uint32_t *res = (uint32_t *)malloc(n * 4u);
                uint8_t *buf = (uint8_t *)malloc(tlen);
                if (!res || !buf) { free(res); free(buf); free(best); return -1; }
                for (uint32_t i = 0; i < n; i++) {
                    if (signed_t) {
                        int64_t v = load_s(vals + i * width, width);
                        res[i] = (uint32_t)(v - (int64_t)base_u);
                    } else {
                        res[i] = (uint32_t)(load_u(vals + i * width, width) - base_u);
                    }
                }
                memset(buf, 0, tlen);
                store_u(buf, width, base_u);
                pack_u32_bits(buf + width, res, n, bw);
                free(res);
                free(best);
                best = buf;
                best_len = tlen;
                best_codec = ETAP_CODEC_FOR;
                best_bw = bw;
            }
        }
    }

    {
        uint8_t *dictp = (uint8_t *)malloc(256u * width);
        uint32_t *idx = (uint32_t *)malloc(n * 4u);
        if (!dictp || !idx) { free(dictp); free(idx); free(best); return -1; }
        uint32_t uniq = 0;
        int overflow = 0;
        for (uint32_t i = 0; i < n; i++) {
            const uint8_t *row = vals + i * width;
            uint32_t found = uniq;
            for (uint32_t k = 0; k < uniq; k++) {
                if (memcmp(dictp + k * width, row, width) == 0) { found = k; break; }
            }
            if (found == uniq) {
                if (uniq >= 256) { overflow = 1; break; }
                memcpy(dictp + uniq * width, row, width);
                found = uniq++;
            }
            idx[i] = found;
        }
        if (!overflow && uniq > 0 && uniq <= n / 2 && uniq <= 256) {
            uint8_t bw = bits_for(uniq > 1 ? uniq - 1 : 1);
            uint32_t dict_start = 4; /* u16 dict_n + 2 pad */
            uint32_t after = align4(dict_start + uniq * width);
            uint32_t tlen = after + packed_words(n, bw) * 4u;
            if (tlen < best_len) {
                uint8_t *buf = (uint8_t *)calloc(1, tlen);
                if (!buf) { free(dictp); free(idx); free(best); return -1; }
                uint16_t dn = (uint16_t)uniq;
                memcpy(buf, &dn, 2);
                memcpy(buf + dict_start, dictp, uniq * width);
                pack_u32_bits(buf + after, idx, n, bw);
                free(best);
                best = buf;
                best_len = tlen;
                best_codec = ETAP_CODEC_DICT;
                best_bw = bw;
            }
        }
        free(dictp);
        free(idx);
    }

    {
        uint32_t n_runs = 1;
        for (uint32_t i = 1; i < n; i++)
            if (memcmp(vals + i * width, vals + (i - 1) * width, width) != 0)
                n_runs++;
        if (n_runs <= n / 4) {
            uint32_t tlen = 4 + n_runs * (width + 4);
            if (tlen < best_len) {
                uint8_t *buf = (uint8_t *)malloc(tlen);
                if (!buf) { free(best); return -1; }
                memcpy(buf, &n_runs, 4);
                uint32_t o = 4, i = 0;
                while (i < n) {
                    uint32_t j = i + 1;
                    while (j < n && memcmp(vals + j * width, vals + i * width, width) == 0)
                        j++;
                    uint32_t rl = j - i;
                    memcpy(buf + o, vals + i * width, width);
                    o += width;
                    memcpy(buf + o, &rl, 4);
                    o += 4;
                    i = j;
                }
                free(best);
                best = buf;
                best_len = tlen;
                best_codec = ETAP_CODEC_RLE;
                best_bw = 0;
            }
        }
    }

    *codec = best_codec;
    *bit_width = best_bw;
    *out = best;
    *out_len = best_len;
    return 0;
}

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
    wb_pad4(w);
    uint32_t start = w->len;
    int any_valid = 0;
    for (int i = 0; i < n_cols; i++)
        if (cols[i].valid) any_valid = 1;
    uint32_t hdr = 4 + 16u * (uint32_t)n_cols;
    if (wb_res(w, hdr) != 0) return -1;
    uint8_t *base = w->p + start;
    uint16_t nc = (uint16_t)n_cols;
    uint16_t fl = any_valid ? 1 : 0;
    memcpy(base + 0, &nc, 2);
    memcpy(base + 2, &fl, 2);
    w->len = start + hdr;

    /* descriptors live at base+4 and stay valid: wbuf does not reallocate. */
    uint8_t *desc_base = base + 4;
    memset(desc_base, 0, 16u * (uint32_t)n_cols);

    for (int i = 0; i < n_cols; i++) {
        wb_pad4(w);
        uint32_t data_off = w->len - start;
        uint32_t payload_len = 0;
        uint8_t codec = ETAP_CODEC_RAW;
        uint8_t bw = 0;
        uint8_t flags = (uint8_t)cols[i].flags;

        if (cols[i].flags & ETAP_COLF_VARLEN) {
            uint32_t offb = 4u * (n_rows + 1u);
            if (wb_res(w, offb + cols[i].values_len) != 0) return -1;
            memcpy(w->p + w->len, cols[i].offsets, offb);
            w->len += offb;
            if (cols[i].values_len) {
                memcpy(w->p + w->len, cols[i].payload, cols[i].values_len);
                w->len += cols[i].values_len;
            }
            payload_len = offb + cols[i].values_len;
            codec = ETAP_CODEC_RAW;
        } else {
            uint8_t *tmp = NULL;
            uint32_t tlen = 0;
            if (encode_fixed(cols[i].payload, n_rows, (uint8_t)cols[i].type,
                             &codec, &bw, &tmp, &tlen) != 0)
                return -1;
            if (wb_res(w, tlen) != 0) { free(tmp); return -1; }
            if (tlen) memcpy(w->p + w->len, tmp, tlen);
            w->len += tlen;
            payload_len = tlen;
            free(tmp);
        }

        if (cols[i].valid) {
            uint32_t vlen = (n_rows + 7u) / 8u;
            if (wb_res(w, vlen) != 0) return -1;
            memset(w->p + w->len, 0, vlen);
            memcpy(w->p + w->len, cols[i].valid, vlen);
            w->len += vlen;
            payload_len += vlen;
            flags |= ETAP_COLF_VALIDITY;
        }

        etap_col_desc d;
        memset(&d, 0, sizeof(d));
        d.col_id = cols[i].col_id;
        d.type = (uint8_t)cols[i].type;
        d.codec = codec;
        d.bit_width = bw;
        d.flags = flags;
        d.data_off = data_off;
        d.data_len = payload_len;
        memcpy(desc_base + 16u * (uint32_t)i, &d, 16);
    }
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

#define PAYLOAD_RESERVE 512u

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
    if (wb_res(&w, PAYLOAD_RESERVE) != 0) return -1;
    memset(buf, 0, PAYLOAD_RESERVE);
    w.len = PAYLOAD_RESERVE;

    sec_tmp secs[16];
    int nsec = 0;
    uint32_t flags = 0;

    uint64_t gap_pkts = s->pending_gap_pkts;
    uint64_t gap_bytes = s->pending_gap_bytes;
    uint64_t gap_first = s->pending_gap_first;
    uint64_t gap_last = s->pending_gap_last;
    if (gap_pkts) flags |= ETAP_BF_HAS_GAP | ETAP_BF_OVERFLOW;

    int any_trunc = 0;
    for (uint32_t i = 0; i < n; i++)
        if (pkts[i].trunc) any_trunc = 1;
    if (any_trunc) flags |= ETAP_BF_TRUNCATED;

    uint8_t slices[512][512];
    uint32_t slen[512], soff[512];
    uint32_t bytes_off = 0, bytes_sz = 0;
    memset(slen, 0, sizeof(slen));
    memset(soff, 0, sizeof(soff));

    if ((cfg->view_mask & ETAP_VIEW_PACKET) &&
        cfg->packet.bytes_mode != ETAP_BYTES_NONE) {
        wb_pad4(&w);
        bytes_off = w.len;
        for (uint32_t i = 0; i < n; i++) {
            soff[i] = w.len - bytes_off;
            slen[i] = slice_packet(&cfg->packet, &pkts[i], slices[i]);
            if (wb_res(&w, slen[i]) != 0) return -1;
            if (slen[i]) memcpy(w.p + w.len, slices[i], slen[i]);
            w.len += slen[i];
        }
        bytes_sz = w.len - bytes_off;
        if (add_section(secs, &nsec, ETAP_SEC_PACKET_BYTES, n, bytes_off, bytes_sz) != 0)
            return -1;
        for (uint32_t i = 0; i < n; i++) {
            if (slen[i] < pkts[i].cap_len && cfg->packet.bytes_mode != ETAP_BYTES_NONE)
                pkts[i].flags |= ETAP_RF_TRUNCATED;
        }
    }

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

        wb_pad4(&w);
        uint32_t off = w.len;
        int sz = write_colgroup(&w, n, cols, nc);
        if (sz < 0) return -1;
        if (add_section(secs, &nsec, ETAP_SEC_PACKET_META, n, off, (uint32_t)sz) != 0)
            return -1;
    }

    uint32_t nparse = 0;
    uint64_t p_pkt[512], p_msg[512];
    uint32_t p_proto[512];
    uint16_t p_moff[512], p_mlen[512], p_pfl[512];
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
            p_pkt[nparse] = pkts[i].pkt_id;
            p_msg[nparse] = pkts[i].pkt_id;
            p_proto[nparse] = (pkts[i].kind == 0) ? ETAP_PROTO_HTTP : ETAP_PROTO_TLS;
            p_moff[nparse] = 54;
            p_pfl[nparse] = 0;
            if (pkts[i].cap_len > 54)
                p_mlen[nparse] = (uint16_t)(pkts[i].cap_len - 54);
            else {
                p_mlen[nparse] = 0;
                p_pfl[nparse] |= ETAP_RF_PARSE_INCOMPLETE;
            }
            if (pkts[i].trunc) p_pfl[nparse] |= ETAP_RF_TRUNCATED;
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

        col_in icols[6];
        int inc = 0;
        icols[inc++] = (col_in){ ETAP_PCOL_PKT_ID,   ETAP_T_U64, 0, p_pkt,   NULL, NULL, 0, 8 };
        icols[inc++] = (col_in){ ETAP_PCOL_MSG_ID,   ETAP_T_U64, 0, p_msg,   NULL, NULL, 0, 8 };
        icols[inc++] = (col_in){ ETAP_PCOL_PROTO_ID, ETAP_T_U32, 0, p_proto, NULL, NULL, 0, 4 };
        icols[inc++] = (col_in){ ETAP_PCOL_MSG_OFF,  ETAP_T_U16, 0, p_moff,  NULL, NULL, 0, 2 };
        icols[inc++] = (col_in){ ETAP_PCOL_MSG_LEN,  ETAP_T_U16, 0, p_mlen,  NULL, NULL, 0, 2 };
        icols[inc++] = (col_in){ ETAP_PCOL_FLAGS,    ETAP_T_U16, 0, p_pfl,   NULL, NULL, 0, 2 };
        wb_pad4(&w);
        uint32_t ioff = w.len;
        int isz = write_colgroup(&w, nparse, icols, inc);
        if (isz < 0) return -1;
        if (add_section(secs, &nsec, ETAP_SEC_PARSE_INDEX, nparse, ioff, (uint32_t)isz) != 0)
            return -1;

        col_in cols[16];
        int nc = 0;
        const parse_sel *ps = &cfg->parse;
        if (has_field(ps, ETAP_FLD_IPV4_SRC))
            cols[nc++] = (col_in){ ETAP_FLD_IPV4_SRC, ETAP_T_IPV4, 0, v_src, val_src, NULL, 0, 4 };
        if (has_field(ps, ETAP_FLD_IPV4_DST))
            cols[nc++] = (col_in){ ETAP_FLD_IPV4_DST, ETAP_T_IPV4, 0, v_dst, val_dst, NULL, 0, 4 };
        if (has_field(ps, ETAP_FLD_TCP_SPORT))
            cols[nc++] = (col_in){ ETAP_FLD_TCP_SPORT, ETAP_T_U16, 0, v_sp, val_sp, NULL, 0, 2 };
        if (has_field(ps, ETAP_FLD_TCP_DPORT))
            cols[nc++] = (col_in){ ETAP_FLD_TCP_DPORT, ETAP_T_U16, 0, v_dp, val_dp, NULL, 0, 2 };
        if (has_field(ps, ETAP_FLD_TLS_SNI))
            cols[nc++] = (col_in){ ETAP_FLD_TLS_SNI, ETAP_T_BYTES, ETAP_COLF_VARLEN | ETAP_COLF_VALIDITY,
                                   sni_heap, val_sni, sni_off, sni_len, 0 };
        if (has_field(ps, ETAP_FLD_HTTP_HOST))
            cols[nc++] = (col_in){ ETAP_FLD_HTTP_HOST, ETAP_T_BYTES, ETAP_COLF_VARLEN | ETAP_COLF_VALIDITY,
                                   host_heap, val_host, host_off, host_len, 0 };
        if (nc > 0) {
            wb_pad4(&w);
            uint32_t off = w.len;
            int sz = write_colgroup(&w, nparse, cols, nc);
            if (sz < 0) return -1;
            if (add_section(secs, &nsec, ETAP_SEC_PARSE_COLS, nparse, off, (uint32_t)sz) != 0)
                return -1;
        }
    }

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
                evs[found].event = pkts[i].new_flow ? 1 : 2;
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
        for (int fi = 0; fi < 3; fi++) {
            sim_flow *f = &s->flows[fi];
            if (f->alive && f->emitted >= flow_budget(f->kind))
                f->alive = 0;
        }

        uint64_t f_id[16], f_start[16], f_last[16], f_p0[16], f_p1[16];
        uint8_t  f_ev[16], f_st[16];
        uint16_t f_fl[16];
        uint32_t f_ifx[16];
        uint64_t ffwd[16], frev[16], bfwd[16], brev[16], dur[16];
        for (uint32_t i = 0; i < ne; i++) {
            f_id[i] = evs[i].flow_id;
            f_ev[i] = evs[i].event;
            f_st[i] = evs[i].state;
            f_fl[i] = evs[i].flags;
            f_ifx[i] = evs[i].ifindex;
            f_start[i] = evs[i].start_ns;
            f_last[i] = evs[i].last_ns;
            f_p0[i] = evs[i].pkt_id_first;
            f_p1[i] = evs[i].pkt_id_last;
            ffwd[i] = evs[i].pkts_fwd;
            frev[i] = evs[i].pkts_rev;
            bfwd[i] = evs[i].bytes_fwd;
            brev[i] = evs[i].bytes_rev;
            dur[i] = evs[i].duration_ns;
        }
        col_in mcols[9];
        int mnc = 0;
        mcols[mnc++] = (col_in){ ETAP_FCOL_FLOW_ID,      ETAP_T_U64,   0, f_id,    NULL, NULL, 0, 8 };
        mcols[mnc++] = (col_in){ ETAP_FCOL_EVENT,        ETAP_T_U8,    0, f_ev,    NULL, NULL, 0, 1 };
        mcols[mnc++] = (col_in){ ETAP_FCOL_STATE,        ETAP_T_U8,    0, f_st,    NULL, NULL, 0, 1 };
        mcols[mnc++] = (col_in){ ETAP_FCOL_FLAGS,        ETAP_T_U16,   0, f_fl,    NULL, NULL, 0, 2 };
        mcols[mnc++] = (col_in){ ETAP_FCOL_IFINDEX,      ETAP_T_U32,   0, f_ifx,   NULL, NULL, 0, 4 };
        mcols[mnc++] = (col_in){ ETAP_FCOL_START_NS,     ETAP_T_TS_NS, 0, f_start, NULL, NULL, 0, 8 };
        mcols[mnc++] = (col_in){ ETAP_FCOL_LAST_NS,      ETAP_T_TS_NS, 0, f_last,  NULL, NULL, 0, 8 };
        mcols[mnc++] = (col_in){ ETAP_FCOL_PKT_ID_FIRST, ETAP_T_U64,   0, f_p0,    NULL, NULL, 0, 8 };
        mcols[mnc++] = (col_in){ ETAP_FCOL_PKT_ID_LAST,  ETAP_T_U64,   0, f_p1,    NULL, NULL, 0, 8 };
        wb_pad4(&w);
        uint32_t moff = w.len;
        int msz = write_colgroup(&w, ne, mcols, mnc);
        if (msz < 0) return -1;
        if (add_section(secs, &nsec, ETAP_SEC_FLOW_META, ne, moff, (uint32_t)msz) != 0)
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
            wb_pad4(&w);
            uint32_t off = w.len;
            int sz = write_colgroup(&w, ne, cols, nc);
            if (sz < 0) return -1;
            if (add_section(secs, &nsec, ETAP_SEC_FLOW_FEAT, ne, off, (uint32_t)sz) != 0)
                return -1;
        }
        if (cfg->flow.flags & 1) {
            uint64_t ids[16 * 64];
            uint32_t nids = 0;
            uint32_t boffs[17];
            boffs[0] = 0;
            for (uint32_t i = 0; i < ne; i++) {
                for (uint32_t k = 0; k < evs[i].n_pkts_idx; k++) {
                    uint32_t pi_ = evs[i].pkt_idx[k];
                    ids[nids++] = pkts[pi_].pkt_id;
                }
                boffs[i + 1] = nids * 8u;
            }
            wb_pad4(&w);
            uint32_t off = w.len;
            col_in pcol = { 1, ETAP_T_U64, ETAP_COLF_VARLEN, ids, NULL, boffs, nids * 8u, 8 };
            int sz = write_colgroup(&w, ne, &pcol, 1);
            if (sz < 0) return -1;
            if (add_section(secs, &nsec, ETAP_SEC_FLOW_PKTS, ne, off, (uint32_t)sz) != 0)
                return -1;
        }
    }

    if (s->schema_needs_embed) {
        flags |= ETAP_BF_SCHEMA_EMBEDDED;
        wb_pad4(&w);
        uint32_t off = w.len;
        uint32_t payload[4] = { s->schema_id, s->epoch, cfg->view_mask, cfg->packet.meta_mask };
        if (wb_res(&w, sizeof(payload)) != 0) return -1;
        memcpy(w.p + w.len, payload, sizeof(payload));
        w.len += sizeof(payload);
        if (add_section(secs, &nsec, ETAP_SEC_SCHEMA, 1, off, w.len - off) != 0)
            return -1;
        s->schema_needs_embed = 0;
    }

    uint32_t hdr_len = gap_pkts ? ETAP_BATCH_HDR_GAP_LEN : ETAP_BATCH_HDR_PREFIX_LEN;
    uint32_t dir_off = hdr_len;
    uint32_t dir_sz = (uint32_t)nsec * ETAP_SECTION_LEN;
    uint32_t new_base = align4(dir_off + dir_sz);
    uint32_t payload_end = w.len;
    uint32_t payload_sz = payload_end - PAYLOAD_RESERVE;
    int32_t shift = (int32_t)new_base - (int32_t)PAYLOAD_RESERVE;
    if (shift > 0) {
        if (wb_res(&w, (uint32_t)shift) != 0) return -1;
        memmove(w.p + new_base, w.p + PAYLOAD_RESERVE, payload_sz);
    } else if (shift < 0) {
        memmove(w.p + new_base, w.p + PAYLOAD_RESERVE, payload_sz);
    }
    w.len = new_base + payload_sz;
    if (new_base > dir_off + dir_sz)
        memset(w.p + dir_off + dir_sz, 0, new_base - (dir_off + dir_sz));
    for (int i = 0; i < nsec; i++)
        secs[i].off = (uint32_t)((int32_t)secs[i].off + shift);

    for (int i = 0; i < nsec; i++) {
        etap_section sc;
        memset(&sc, 0, sizeof(sc));
        sc.kind = (uint8_t)secs[i].kind;
        sc.flags = 0;
        sc.count = secs[i].count;
        sc.off = secs[i].off;
        sc.size = secs[i].size;
        memcpy(w.p + dir_off + (uint32_t)i * ETAP_SECTION_LEN, &sc, ETAP_SECTION_LEN);
    }
    uint32_t total = w.len;

    etap_batch_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = ETAP_MAGIC;
    hdr.version = ETAP_VERSION;
    hdr.hdr_len = (uint16_t)hdr_len;
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
    hdr.producer_lag_us = 0;
    hdr.crc32c = 0;
    hdr.sections_off = dir_off;
    hdr.total_size = total;
    hdr.gap_dropped_pkts = gap_pkts;
    hdr.gap_dropped_bytes = gap_bytes;
    hdr.gap_first_pkt_id = gap_first;
    hdr.gap_last_pkt_id = gap_last;
    memcpy(buf, &hdr, ETAP_BATCH_HDR_PREFIX_LEN);
    if (gap_pkts)
        memcpy(buf + ETAP_BATCH_HDR_PREFIX_LEN,
               (const uint8_t *)&hdr + ETAP_BATCH_HDR_PREFIX_LEN,
               ETAP_BATCH_GAP_BLOCK_LEN);

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

static int decode_batch_hdr(const uint8_t *buf, uint32_t size, etap_batch_hdr *out);
static void free_batch_cache(etap_batch *b);

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
    if (decode_batch_hdr(b->buf, b->size, &b->hdr) != 0) {
        free(b);
        sl->state = SLOT_READY;
        return NULL;
    }
    b->hdr_ok = 1;
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
    free_batch_cache(batch);
    free(batch);
    return ETAP_OK;
}

static int decode_batch_hdr(const uint8_t *buf, uint32_t size, etap_batch_hdr *out)
{
    memset(out, 0, sizeof(*out));
    if (!buf || size < ETAP_BATCH_HDR_PREFIX_LEN) return -1;
    memcpy(out, buf, ETAP_BATCH_HDR_PREFIX_LEN);
    if (out->magic != ETAP_MAGIC || out->version != ETAP_VERSION) return -1;
    if (out->hdr_len < ETAP_BATCH_HDR_PREFIX_LEN || out->hdr_len > size) return -1;
    if (out->flags & ETAP_BF_HAS_GAP) {
        if (out->hdr_len < ETAP_BATCH_HDR_GAP_LEN || size < ETAP_BATCH_HDR_GAP_LEN) return -1;
        memcpy((uint8_t *)out + ETAP_BATCH_HDR_PREFIX_LEN,
               buf + ETAP_BATCH_HDR_PREFIX_LEN,
               ETAP_BATCH_GAP_BLOCK_LEN);
    }
    if (out->total_size > size || out->total_size < out->hdr_len) return -1;
    if ((uint64_t)out->sections_off + (uint64_t)out->n_sections * ETAP_SECTION_LEN > out->total_size)
        return -1;
    return 0;
}

static void free_batch_cache(etap_batch *b)
{
    if (!b) return;
    for (uint32_t i = 0; i < b->n_cache; i++) {
        if (b->cache[i].owned) {
            free(b->cache[i].data);
            /* valid and offsets alias the raw buffer unless owned together;
             * owned allocations are only the native data array. */
        }
    }
    free(b->cache);
    b->cache = NULL;
    b->n_cache = b->cap_cache = 0;
    free(b->parse_rows);
    b->parse_rows = NULL;
    b->n_parse_rows = 0;
    b->parse_ready = 0;
    free(b->flow_rows);
    b->flow_rows = NULL;
    b->n_flow_rows = 0;
    b->flow_ready = 0;
}

static etap_status read_section(const etap_batch *b, uint16_t index, etap_section *out)
{
    if (!b || !b->hdr_ok || !out) return ETAP_INVALID;
    if (index >= b->hdr.n_sections) return ETAP_INVALID;
    uint32_t off = b->hdr.sections_off + (uint32_t)index * ETAP_SECTION_LEN;
    if (off + ETAP_SECTION_LEN > b->size) return ETAP_SCHEMA;
    memcpy(out, b->buf + off, ETAP_SECTION_LEN);
    return ETAP_OK;
}

etap_status etap_batch_section(const etap_batch *batch, uint16_t index, etap_section *out)
{
    return read_section(batch, index, out);
}

static int find_sec(const etap_batch *b, uint16_t kind, etap_section *out)
{
    if (!b || !b->hdr_ok) return 0;
    for (uint16_t i = 0; i < b->hdr.n_sections; i++) {
        etap_section s;
        if (read_section(b, i, &s) != ETAP_OK) return 0;
        if (s.kind == kind) {
            if (out) *out = s;
            return 1;
        }
    }
    return 0;
}

static etap_status unpack_col(const etap_batch *batch, const etap_section *s,
                              uint32_t col_id, col_cache_ent *e)
{
    if (s->size < 4 || s->off + s->size > batch->size) return ETAP_SCHEMA;
    const uint8_t *base = batch->buf + s->off;
    uint16_t n_cols = 0, gflags = 0;
    memcpy(&n_cols, base + 0, 2);
    memcpy(&gflags, base + 2, 2);
    (void)gflags;
    if (4u + 16u * n_cols > s->size) return ETAP_SCHEMA;
    etap_col_desc d;
    int found = 0;
    for (uint16_t i = 0; i < n_cols; i++) {
        memcpy(&d, base + 4 + 16u * i, 16);
        if (d.col_id == col_id) { found = 1; break; }
    }
    if (!found) return ETAP_INVALID;
    uint32_t n_rows = s->count;
    if (d.data_off + d.data_len > s->size) return ETAP_SCHEMA;
    const uint8_t *dp = base + d.data_off;
    uint32_t remain = d.data_len;
    const uint8_t *valid = NULL;
    if (d.flags & ETAP_COLF_VALIDITY) {
        uint32_t vlen = (n_rows + 7u) / 8u;
        if (remain < vlen) return ETAP_SCHEMA;
        valid = dp + (remain - vlen);
        remain -= vlen;
    }

    memset(e, 0, sizeof(*e));
    e->type = (etap_type)d.type;
    e->n = n_rows;
    e->valid = (uint8_t *)valid;

    if (d.flags & ETAP_COLF_VARLEN) {
        uint32_t offb = 4u * (n_rows + 1u);
        if (remain < offb) return ETAP_SCHEMA;
        e->offsets = (uint32_t *)(void *)(dp);
        e->data = (uint8_t *)(void *)(dp + offb);
        e->owned = 0;
        return ETAP_OK;
    }

    uint32_t width = type_width(d.type);
    if (d.codec == ETAP_CODEC_RAW) {
        e->data = (uint8_t *)(void *)dp;
        e->owned = 0;
        return ETAP_OK;
    }

    uint32_t nbytes = n_rows * width;
    uint8_t *arr = (uint8_t *)calloc(1, nbytes ? nbytes : 1u);
    if (!arr) return ETAP_NOMEM;

    if (d.codec == ETAP_CODEC_CONST) {
        if (remain < width) { free(arr); return ETAP_SCHEMA; }
        for (uint32_t i = 0; i < n_rows; i++)
            memcpy(arr + i * width, dp, width);
    } else if (d.codec == ETAP_CODEC_FOR) {
        if (remain < width) { free(arr); return ETAP_SCHEMA; }
        uint8_t bw = d.bit_width;
        if (bw < 1 || bw > 32) { free(arr); return ETAP_SCHEMA; }
        uint32_t plen = packed_words(n_rows, bw) * 4u;
        if (remain < width + plen) { free(arr); return ETAP_SCHEMA; }
        uint64_t base_u = load_u(dp, width);
        uint32_t *res = (uint32_t *)malloc(n_rows ? n_rows * 4u : 4u);
        if (!res) { free(arr); return ETAP_NOMEM; }
        unpack_u32_bits(res, dp + width, n_rows, bw);
        for (uint32_t i = 0; i < n_rows; i++) {
            if (is_signed_type(d.type)) {
                int64_t v = (int64_t)base_u + (int64_t)res[i];
                store_u(arr + i * width, width, (uint64_t)v);
            } else {
                store_u(arr + i * width, width, base_u + (uint64_t)res[i]);
            }
        }
        free(res);
    } else if (d.codec == ETAP_CODEC_DELTA) {
        if (remain < width) { free(arr); return ETAP_SCHEMA; }
        memcpy(arr, dp, width);
        uint32_t nd = n_rows > 0 ? n_rows - 1 : 0;
        if (nd) {
            uint8_t bw = d.bit_width;
            if (bw < 1 || bw > 32) { free(arr); return ETAP_SCHEMA; }
            uint32_t plen = packed_words(nd, bw) * 4u;
            if (remain < width + plen) { free(arr); return ETAP_SCHEMA; }
            uint32_t *dz = (uint32_t *)malloc(nd * 4u);
            if (!dz) { free(arr); return ETAP_NOMEM; }
            unpack_u32_bits(dz, dp + width, nd, bw);
            uint64_t cur = load_u(arr, width);
            for (uint32_t i = 0; i < nd; i++) {
                int64_t dlt = unzigzag64(dz[i]);
                cur = (uint64_t)((int64_t)cur + dlt);
                store_u(arr + (i + 1) * width, width, cur);
            }
            free(dz);
        }
    } else if (d.codec == ETAP_CODEC_DICT) {
        if (remain < 2) { free(arr); return ETAP_SCHEMA; }
        uint16_t dict_n = 0;
        memcpy(&dict_n, dp, 2);
        uint32_t dict_start = 4;
        uint32_t dict_bytes = (uint32_t)dict_n * width;
        if (remain < dict_start + dict_bytes) { free(arr); return ETAP_SCHEMA; }
        const uint8_t *dict = dp + dict_start;
        uint32_t after = align4(dict_start + dict_bytes);
        uint8_t bw = d.bit_width;
        if (bw < 1 || bw > 32) { free(arr); return ETAP_SCHEMA; }
        uint32_t plen = packed_words(n_rows, bw) * 4u;
        if (remain < after + plen) { free(arr); return ETAP_SCHEMA; }
        uint32_t *idx = (uint32_t *)malloc(n_rows ? n_rows * 4u : 4u);
        if (!idx) { free(arr); return ETAP_NOMEM; }
        unpack_u32_bits(idx, dp + after, n_rows, bw);
        for (uint32_t i = 0; i < n_rows; i++) {
            if (idx[i] >= dict_n) { free(idx); free(arr); return ETAP_SCHEMA; }
            memcpy(arr + i * width, dict + idx[i] * width, width);
        }
        free(idx);
    } else if (d.codec == ETAP_CODEC_RLE) {
        if (remain < 4) { free(arr); return ETAP_SCHEMA; }
        uint32_t n_runs = 0;
        memcpy(&n_runs, dp, 4);
        uint32_t o = 4, row = 0;
        for (uint32_t r = 0; r < n_runs; r++) {
            if (o + width + 4 > remain) { free(arr); return ETAP_SCHEMA; }
            uint32_t rl = 0;
            memcpy(&rl, dp + o + width, 4);
            if (row + rl > n_rows) { free(arr); return ETAP_SCHEMA; }
            for (uint32_t k = 0; k < rl; k++, row++)
                memcpy(arr + row * width, dp + o, width);
            o += width + 4;
        }
        if (row != n_rows) { free(arr); return ETAP_SCHEMA; }
    } else {
        free(arr);
        return ETAP_SCHEMA;
    }

    e->data = arr;
    e->owned = 1;
    return ETAP_OK;
}

const etap_batch_hdr *etap_batch_header(const etap_batch *batch)
{
    return (batch && batch->hdr_ok) ? &batch->hdr : NULL;
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
    if (!batch || !batch->hdr_ok) return ETAP_INVALID;
    etap_batch *mb = (etap_batch *)batch;
    for (uint32_t i = 0; i < mb->n_cache; i++) {
        if (mb->cache[i].section_kind == section_kind && mb->cache[i].col_id == col_id) {
            col_cache_ent *e = &mb->cache[i];
            if (type) *type = e->type;
            if (n) *n = e->n;
            if (data) *data = e->data;
            if (valid) *valid = e->valid;
            if (offsets) *offsets = e->offsets;
            return ETAP_OK;
        }
    }
    etap_section s;
    if (!find_sec(batch, section_kind, &s)) return ETAP_SCHEMA;
    if (mb->n_cache == mb->cap_cache) {
        uint32_t nc = mb->cap_cache ? mb->cap_cache * 2u : 16u;
        col_cache_ent *nb = (col_cache_ent *)realloc(mb->cache, nc * sizeof(*nb));
        if (!nb) return ETAP_NOMEM;
        mb->cache = nb;
        mb->cap_cache = nc;
    }
    col_cache_ent e;
    etap_status st = unpack_col(batch, &s, col_id, &e);
    if (st != ETAP_OK) return st;
    e.section_kind = section_kind;
    e.col_id = col_id;
    mb->cache[mb->n_cache++] = e;
    if (type) *type = e.type;
    if (n) *n = e.n;
    if (data) *data = e.data;
    if (valid) *valid = e.valid;
    if (offsets) *offsets = e.offsets;
    return ETAP_OK;
}

const etap_parse_index_row *etap_parse_index(const etap_batch *batch, uint32_t *n)
{
    if (n) *n = 0;
    if (!batch || !batch->hdr_ok) return NULL;
    etap_batch *mb = (etap_batch *)batch;
    if (mb->parse_ready) {
        if (n) *n = mb->n_parse_rows;
        return mb->parse_rows;
    }
    etap_section s;
    if (!find_sec(batch, ETAP_SEC_PARSE_INDEX, &s) || s.count == 0) {
        mb->parse_ready = 1;
        mb->n_parse_rows = 0;
        mb->parse_rows = NULL;
        return NULL;
    }
    uint32_t nr = s.count;
    etap_parse_index_row *rows = (etap_parse_index_row *)calloc(nr, sizeof(*rows));
    if (!rows) return NULL;
    etap_type t;
    uint32_t n1 = 0;
    const uint64_t *pkt = NULL, *msg = NULL;
    const uint32_t *proto = NULL;
    const uint16_t *moff = NULL, *mlen = NULL, *fl = NULL;
    if (etap_col(batch, ETAP_SEC_PARSE_INDEX, ETAP_PCOL_PKT_ID, &t, &n1, (const void **)&pkt, NULL, NULL) == ETAP_OK && pkt)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].pkt_id = pkt[i];
    if (etap_col(batch, ETAP_SEC_PARSE_INDEX, ETAP_PCOL_MSG_ID, &t, &n1, (const void **)&msg, NULL, NULL) == ETAP_OK && msg)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].msg_id = msg[i];
    if (etap_col(batch, ETAP_SEC_PARSE_INDEX, ETAP_PCOL_PROTO_ID, &t, &n1, (const void **)&proto, NULL, NULL) == ETAP_OK && proto)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].proto_id = proto[i];
    if (etap_col(batch, ETAP_SEC_PARSE_INDEX, ETAP_PCOL_MSG_OFF, &t, &n1, (const void **)&moff, NULL, NULL) == ETAP_OK && moff)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].msg_off = moff[i];
    if (etap_col(batch, ETAP_SEC_PARSE_INDEX, ETAP_PCOL_MSG_LEN, &t, &n1, (const void **)&mlen, NULL, NULL) == ETAP_OK && mlen)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].msg_len = mlen[i];
    if (etap_col(batch, ETAP_SEC_PARSE_INDEX, ETAP_PCOL_FLAGS, &t, &n1, (const void **)&fl, NULL, NULL) == ETAP_OK && fl)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].flags = fl[i];
    mb->parse_rows = rows;
    mb->n_parse_rows = nr;
    mb->parse_ready = 1;
    if (n) *n = nr;
    return rows;
}

const etap_flow_meta_row *etap_flow_meta(const etap_batch *batch, uint32_t *n)
{
    if (n) *n = 0;
    if (!batch || !batch->hdr_ok) return NULL;
    etap_batch *mb = (etap_batch *)batch;
    if (mb->flow_ready) {
        if (n) *n = mb->n_flow_rows;
        return mb->flow_rows;
    }
    etap_section s;
    if (!find_sec(batch, ETAP_SEC_FLOW_META, &s) || s.count == 0) {
        mb->flow_ready = 1;
        mb->n_flow_rows = 0;
        mb->flow_rows = NULL;
        return NULL;
    }
    uint32_t nr = s.count;
    etap_flow_meta_row *rows = (etap_flow_meta_row *)calloc(nr, sizeof(*rows));
    if (!rows) return NULL;
    etap_type t;
    uint32_t n1 = 0;
    const uint64_t *fid = NULL, *t0 = NULL, *t1 = NULL, *p0 = NULL, *p1 = NULL;
    const uint8_t *ev = NULL, *st = NULL;
    const uint16_t *fl = NULL;
    const uint32_t *ifx = NULL;
    if (etap_col(batch, ETAP_SEC_FLOW_META, ETAP_FCOL_FLOW_ID, &t, &n1, (const void **)&fid, NULL, NULL) == ETAP_OK && fid)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].flow_id = fid[i];
    if (etap_col(batch, ETAP_SEC_FLOW_META, ETAP_FCOL_EVENT, &t, &n1, (const void **)&ev, NULL, NULL) == ETAP_OK && ev)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].event = ev[i];
    if (etap_col(batch, ETAP_SEC_FLOW_META, ETAP_FCOL_STATE, &t, &n1, (const void **)&st, NULL, NULL) == ETAP_OK && st)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].state = st[i];
    if (etap_col(batch, ETAP_SEC_FLOW_META, ETAP_FCOL_FLAGS, &t, &n1, (const void **)&fl, NULL, NULL) == ETAP_OK && fl)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].flags = fl[i];
    if (etap_col(batch, ETAP_SEC_FLOW_META, ETAP_FCOL_IFINDEX, &t, &n1, (const void **)&ifx, NULL, NULL) == ETAP_OK && ifx)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].ifindex = ifx[i];
    if (etap_col(batch, ETAP_SEC_FLOW_META, ETAP_FCOL_START_NS, &t, &n1, (const void **)&t0, NULL, NULL) == ETAP_OK && t0)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].start_ns = t0[i];
    if (etap_col(batch, ETAP_SEC_FLOW_META, ETAP_FCOL_LAST_NS, &t, &n1, (const void **)&t1, NULL, NULL) == ETAP_OK && t1)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].last_ns = t1[i];
    if (etap_col(batch, ETAP_SEC_FLOW_META, ETAP_FCOL_PKT_ID_FIRST, &t, &n1, (const void **)&p0, NULL, NULL) == ETAP_OK && p0)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].pkt_id_first = p0[i];
    if (etap_col(batch, ETAP_SEC_FLOW_META, ETAP_FCOL_PKT_ID_LAST, &t, &n1, (const void **)&p1, NULL, NULL) == ETAP_OK && p1)
        for (uint32_t i = 0; i < nr && i < n1; i++) rows[i].pkt_id_last = p1[i];
    mb->flow_rows = rows;
    mb->n_flow_rows = nr;
    mb->flow_ready = 1;
    if (n) *n = nr;
    return rows;
}

etap_span etap_packet_bytes(const etap_batch *batch, uint32_t index)
{
    etap_span sp = { NULL, 0 };
    etap_section bytes;
    if (!find_sec(batch, ETAP_SEC_PACKET_BYTES, &bytes)) return sp;
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
    if ((uint64_t)off + len > bytes.size) return sp;
    sp.data = batch->buf + bytes.off + off;
    sp.len = len;
    return sp;
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
