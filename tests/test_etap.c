#include "etap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int g_pass, g_fail, g_cur_fail;
static const char *g_case;

#define CASE(name) \
    do { \
        if (g_case) finish_case(); \
        g_case = (name); \
        g_cur_fail = 0; \
    } while (0)

static void finish_case(void)
{
    if (!g_case) return;
    if (g_cur_fail == 0) {
        g_pass++;
        printf("  [通过] %s\n", g_case);
    } else {
        g_fail++;
        printf("  [失败] %s（%d 处断言失败）\n", g_case, g_cur_fail);
    }
    g_case = NULL;
}

#define CHECK(cond, fmt, ...) \
    do { \
        if (!(cond)) { \
            g_cur_fail++; \
            fprintf(stderr, "    断言失败 @%s:%d: " fmt "\n", \
                    __FILE__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

static void build_full_req(uint8_t *buf, uint32_t *len,
                           uint32_t view_mask, uint32_t max_records,
                           uint32_t meta_mask, uint8_t bytes_mode, uint16_t max_bytes,
                           const uint32_t *fields, uint16_t n_fields,
                           const uint32_t *feats, uint16_t n_feats,
                           uint32_t flags)
{
    memset(buf, 0, 512);
    uint32_t off = (uint32_t)sizeof(etap_sub_req_hdr);

    etap_packet_sel_hdr pk;
    memset(&pk, 0, sizeof(pk));
    pk.meta_mask = meta_mask;
    pk.bytes_mode = bytes_mode;
    pk.max_bytes = max_bytes;
    uint32_t packet_off = off;
    memcpy(buf + off, &pk, sizeof(pk));
    off += (uint32_t)sizeof(pk);

    uint32_t parse_off = off;
    uint16_t pflags = 3, n_protos = 0, reserved = 0;
    memcpy(buf + off, &pflags, 2); off += 2;
    memcpy(buf + off, &n_protos, 2); off += 2;
    memcpy(buf + off, &n_fields, 2); off += 2;
    memcpy(buf + off, &reserved, 2); off += 2;
    if (n_fields) {
        memcpy(buf + off, fields, 4u * n_fields);
        off += 4u * n_fields;
    }

    uint32_t flow_off = off;
    uint16_t ev = 0x1F, fl = 1, rf = 0;
    memcpy(buf + off, &ev, 2); off += 2;
    memcpy(buf + off, &fl, 2); off += 2;
    memcpy(buf + off, &n_feats, 2); off += 2;
    memcpy(buf + off, &rf, 2); off += 2;
    if (n_feats) {
        memcpy(buf + off, feats, 4u * n_feats);
        off += 4u * n_feats;
    }

    etap_sub_req_hdr h;
    memset(&h, 0, sizeof(h));
    h.req_len = off;
    h.flags = flags;
    h.view_mask = view_mask;
    h.max_records = max_records;
    h.max_bytes = 65536;
    h.max_wait_us = 0;
    h.packet_off = packet_off;
    h.parse_off = parse_off;
    h.flow_off = flow_off;
    memcpy(buf, &h, sizeof(h));
    *len = off;
}

static uint16_t rd_u16be(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t rd_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int catalog_has_name(const etap_caps *caps, uint32_t field_id, const char *name)
{
    const etap_caps_hdr *h = etap_caps_header(caps);
    const uint8_t *base = etap_caps_data(caps, NULL);
    const etap_field_desc *fd = (const etap_field_desc *)(base + h->fields_off);
    const char *strtab = (const char *)(base + h->strtab_off);
    for (uint16_t i = 0; i < h->n_fields; i++) {
        if (fd[i].field_id == field_id) {
            return strncmp(strtab + fd[i].name_off, name, fd[i].name_len) == 0 &&
                   strtab[fd[i].name_off + fd[i].name_len] == 0;
        }
    }
    return 0;
}

static int section_present(const etap_batch *b, uint16_t kind)
{
    const etap_batch_hdr *h = etap_batch_header(b);
    if (!h) return 0;
    for (uint16_t i = 0; i < h->n_sections; i++) {
        etap_section s;
        if (etap_batch_section(b, i, &s) == ETAP_OK && s.kind == kind) return 1;
    }
    return 0;
}

static uint32_t align8_u(uint32_t x) { return (x + 7u) & ~7u; }

/* Conservative v0.1 (TAP1) size of the same logical content: 128-byte header,
 * 24-byte section entries, 8-byte-aligned packet slices, native-width columns,
 * 32-byte parse-index rows and 48-byte flow-meta rows. */
static uint32_t v01_equivalent_size(const etap_batch *b)
{
    const etap_batch_hdr *h = etap_batch_header(b);
    uint32_t np = h->n_parse_rows, nf = h->n_flows;
    uint32_t sz = 128u + 24u * h->n_sections;

    etap_type t;
    uint32_t nc = 0;
    const uint32_t *blen = NULL;
    if (etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_BYTES_LEN, &t, &nc, (const void **)&blen, NULL, NULL) == ETAP_OK && blen) {
        uint32_t bytes = 0;
        for (uint32_t i = 0; i < nc; i++) {
            bytes = align8_u(bytes);
            bytes += blen[i];
        }
        bytes = align8_u(bytes);
        sz += bytes;
    }

    /* Packet meta columns at native width, each 8-byte padded. */
    struct { uint32_t id; uint32_t width; } pcols[] = {
        { ETAP_COL_PKT_ID, 8 }, { ETAP_COL_FLOW_ID, 8 }, { ETAP_COL_TS_NS, 8 },
        { ETAP_COL_WIRE_LEN, 4 }, { ETAP_COL_CAP_LEN, 4 }, { ETAP_COL_DIR, 1 },
        { ETAP_COL_IFINDEX, 4 }, { ETAP_COL_FLAGS, 2 }, { ETAP_COL_L3_OFF, 2 },
        { ETAP_COL_L4_OFF, 2 }, { ETAP_COL_BYTES_OFF, 4 }, { ETAP_COL_BYTES_LEN, 4 }
    };
    uint32_t meta_cols = 0;
    uint32_t meta_data = 0;
    for (unsigned i = 0; i < sizeof(pcols) / sizeof(pcols[0]); i++) {
        const void *d = NULL;
        uint32_t nn = 0;
        if (etap_col(b, ETAP_SEC_PACKET_META, pcols[i].id, &t, &nn, &d, NULL, NULL) == ETAP_OK) {
            meta_cols++;
            meta_data = align8_u(meta_data);
            meta_data += nn * pcols[i].width;
        }
    }
    if (meta_cols)
        sz += align8_u(8u + 16u * meta_cols + align8_u(meta_data));

    if (np)
        sz += align8_u(np * 32u);

    /* Parse field columns (validity 8-aligned + native / varlen). */
    uint32_t parse_cols = 0, parse_data = 0;
    uint32_t pf[4] = { ETAP_FLD_IPV4_SRC, ETAP_FLD_IPV4_DST, ETAP_FLD_TCP_SPORT, ETAP_FLD_TCP_DPORT };
    uint32_t pw[4] = { 4, 4, 2, 2 };
    for (int i = 0; i < 4; i++) {
        const void *d = NULL; uint32_t nn = 0;
        if (etap_col(b, ETAP_SEC_PARSE_COLS, pf[i], &t, &nn, &d, NULL, NULL) == ETAP_OK) {
            parse_cols++;
            parse_data = align8_u(parse_data);
            parse_data += align8_u((nn + 7u) / 8u);
            parse_data += nn * pw[i];
        }
    }
    const void *vd = NULL; const uint8_t *vv = NULL; const uint32_t *vo = NULL; uint32_t nn = 0;
    if (etap_col(b, ETAP_SEC_PARSE_COLS, ETAP_FLD_TLS_SNI, &t, &nn, &vd, &vv, &vo) == ETAP_OK && vo) {
        parse_cols++;
        parse_data = align8_u(parse_data);
        parse_data += align8_u((nn + 7u) / 8u);
        parse_data += 4u * (nn + 1u) + vo[nn];
    }
    if (etap_col(b, ETAP_SEC_PARSE_COLS, ETAP_FLD_HTTP_HOST, &t, &nn, &vd, &vv, &vo) == ETAP_OK && vo) {
        parse_cols++;
        parse_data = align8_u(parse_data);
        parse_data += align8_u((nn + 7u) / 8u);
        parse_data += 4u * (nn + 1u) + vo[nn];
    }
    if (parse_cols)
        sz += align8_u(8u + 16u * parse_cols + align8_u(parse_data));

    if (nf)
        sz += align8_u(nf * 48u);

    uint32_t feats[5] = { ETAP_FEAT_PKTS_FWD, ETAP_FEAT_PKTS_REV, ETAP_FEAT_BYTES_FWD, ETAP_FEAT_BYTES_REV, ETAP_FEAT_DURATION };
    uint32_t fc = 0, fd = 0;
    for (int i = 0; i < 5; i++) {
        const void *d = NULL; uint32_t nnn = 0;
        if (etap_col(b, ETAP_SEC_FLOW_FEAT, feats[i], &t, &nnn, &d, NULL, NULL) == ETAP_OK) {
            fc++;
            fd = align8_u(fd);
            fd += nnn * 8u;
        }
    }
    if (fc)
        sz += align8_u(8u + 16u * fc + align8_u(fd));

    const uint32_t *fo = NULL; const void *fv = NULL;
    if (etap_col(b, ETAP_SEC_FLOW_PKTS, 1, &t, &nn, &fv, NULL, &fo) == ETAP_OK && fo) {
        sz += align8_u(8u + 16u + align8_u(4u * (nn + 1u) + fo[nn]));
    }

    /* SCHEMA section payload was 16 bytes plus padding. */
    if (h->flags & ETAP_BF_SCHEMA_EMBEDDED)
        sz += align8_u(16u);
    return sz;
}

static int col_present(const etap_batch *b, uint16_t kind, uint32_t col)
{
    etap_type t;
    uint32_t n;
    const void *d;
    return etap_col(b, kind, col, &t, &n, &d, NULL, NULL) == ETAP_OK;
}

int main(void)
{
    printf("ETAP 接口验证（参考实现 / 模拟端口 etap://sim）\n");

    /* 1. 拒绝非法 URI */
    CASE("open 拒绝非模拟 URI");
    {
        etap_conn *c = NULL;
        CHECK(etap_open("http://example", NULL, &c) == ETAP_INVALID, "应拒绝非法 URI");
        CHECK(c == NULL, "失败时不得返回连接");
        CHECK(etap_open(NULL, NULL, &c) == ETAP_INVALID, "应拒绝空 URI");
    }

    /* 2. discover */
    CASE("能力发现目录与魔数");
    etap_conn *conn = NULL;
    CHECK(etap_open("etap://sim", NULL, &conn) == ETAP_OK, "open sim");
    CHECK(conn != NULL, "连接非空");
    etap_caps *caps = NULL;
    CHECK(etap_discover(conn, &caps) == ETAP_OK, "discover");
    const etap_caps_hdr *ch = etap_caps_header(caps);
    CHECK(ch && ch->magic == ETAP_MAGIC, "caps magic");
    CHECK(ch->version == ETAP_VERSION, "version");
    CHECK(ch->endian == 0, "小端");
    CHECK((ch->view_mask & (ETAP_VIEW_PACKET | ETAP_VIEW_PARSE | ETAP_VIEW_FLOW)) ==
              (ETAP_VIEW_PACKET | ETAP_VIEW_PARSE | ETAP_VIEW_FLOW),
          "三种视图都支持");
    CHECK(ch->n_fields == 6 && ch->n_features == 5 && ch->n_protos == 5, "目录项数量");
    CHECK(catalog_has_name(caps, ETAP_FLD_TCP_SPORT, "tcp.sport"), "tcp.sport 目录名");
    CHECK(catalog_has_name(caps, ETAP_FLD_TLS_SNI, "tls.sni"), "tls.sni 目录名");
    /* 热路径 ID 不得依赖字符串，但目录本身可以有名字 */
    etap_caps_free(caps);

    uint32_t all_fields[] = {
        ETAP_FLD_IPV4_SRC, ETAP_FLD_IPV4_DST, ETAP_FLD_TCP_SPORT,
        ETAP_FLD_TCP_DPORT, ETAP_FLD_TLS_SNI, ETAP_FLD_HTTP_HOST
    };
    uint32_t all_feats[] = {
        ETAP_FEAT_PKTS_FWD, ETAP_FEAT_PKTS_REV,
        ETAP_FEAT_BYTES_FWD, ETAP_FEAT_BYTES_REV, ETAP_FEAT_DURATION
    };
    uint8_t reqbuf[512];
    uint32_t reqlen = 0;
    build_full_req(reqbuf, &reqlen,
                   ETAP_VIEW_PACKET | ETAP_VIEW_PARSE | ETAP_VIEW_FLOW,
                   8, 0x0FFF, ETAP_BYTES_PREFIX, 128,
                   all_fields, 6, all_feats, 5, 0);
    etap_sub_req req = { reqbuf, reqlen };

    CASE("订阅后交付合法批次头");
    etap_sub *sub = NULL;
    CHECK(etap_subscribe(conn, &req, &sub) == ETAP_OK, "subscribe");
    etap_batch *b = NULL;
    CHECK(etap_poll(sub, 0, &b) == ETAP_OK && b, "poll");
    const etap_batch_hdr *bh = etap_batch_header(b);
    CHECK(bh->magic == ETAP_MAGIC, "batch magic 0x%x", bh->magic);
    CHECK(bh->hdr_len == ETAP_BATCH_HDR_PREFIX_LEN, "无缺口时 hdr_len=%u 应为 92", bh->hdr_len);
    CHECK(bh->version == ETAP_VERSION, "version");
    CHECK(sizeof(*bh) == 124, "decoded header 含 gap 字段，应为 124，得到 %zu", sizeof(*bh));
    uint32_t rawsz = 0;
    const uint8_t *raw = etap_batch_data(b, &rawsz);
    CHECK(raw && rawsz == bh->total_size && rawsz >= bh->hdr_len, "total_size 与缓冲一致 %u/%u", rawsz, bh->total_size);
    CHECK(bh->n_packets > 0 && bh->n_packets <= 8, "n_packets=%u", bh->n_packets);
    CHECK(bh->n_parse_rows == bh->n_packets, "解析行与报文对齐");
    CHECK(bh->n_flows > 0, "含流视图");
    CHECK(bh->seq == 0, "首批 seq=0");
    CHECK(bh->epoch == 1, "epoch=1");
    CHECK(bh->time_last_ns >= bh->time_first_ns, "时间窗有序");
    CHECK(bh->sections_off == bh->hdr_len, "节目录紧随批次头 sections_off=%u hdr_len=%u", bh->sections_off, bh->hdr_len);
    CHECK(bh->sections_off + ETAP_SECTION_LEN * bh->n_sections <= bh->total_size, "节目录越界");
    CHECK((bh->flags & ETAP_BF_HAS_GAP) == 0, "首批无缺口");
    CHECK(bh->gap_dropped_pkts == 0 && bh->gap_dropped_bytes == 0, "解码头的 gap 字段应为 0");
    CHECK((bh->flags & ETAP_BF_SCHEMA_EMBEDDED) != 0, "首批应内嵌 schema");
    CHECK(section_present(b, ETAP_SEC_PACKET_META), "PACKET_META");
    CHECK(section_present(b, ETAP_SEC_PACKET_BYTES), "PACKET_BYTES");
    CHECK(section_present(b, ETAP_SEC_PARSE_INDEX), "PARSE_INDEX");
    CHECK(section_present(b, ETAP_SEC_PARSE_COLS), "PARSE_COLS");
    CHECK(section_present(b, ETAP_SEC_FLOW_META), "FLOW_META");
    CHECK(section_present(b, ETAP_SEC_FLOW_FEAT), "FLOW_FEAT");

    CASE("报文视图：标识递增、切片与方向");
    {
        etap_type t;
        uint32_t n = 0;
        const uint64_t *ids = NULL, *fids = NULL, *ts = NULL;
        const uint32_t *wire = NULL, *cap = NULL;
        const uint16_t *fl = NULL;
        const uint8_t *dir = NULL;
        CHECK(etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_PKT_ID, &t, &n, (const void **)&ids, NULL, NULL) == ETAP_OK, "pkt_id 列");
        CHECK(t == ETAP_T_U64 && n == bh->n_packets, "pkt_id 类型与行数");
        CHECK(etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_FLOW_ID, &t, &n, (const void **)&fids, NULL, NULL) == ETAP_OK, "flow_id");
        CHECK(etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_TS_NS, &t, &n, (const void **)&ts, NULL, NULL) == ETAP_OK, "ts");
        CHECK(etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_WIRE_LEN, &t, &n, (const void **)&wire, NULL, NULL) == ETAP_OK, "wire");
        CHECK(etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_CAP_LEN, &t, &n, (const void **)&cap, NULL, NULL) == ETAP_OK, "cap");
        CHECK(etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_FLAGS, &t, &n, (const void **)&fl, NULL, NULL) == ETAP_OK, "flags");
        CHECK(etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_DIR, &t, &n, (const void **)&dir, NULL, NULL) == ETAP_OK, "dir");
        CHECK(ids[0] == 1, "首个 pkt_id 从 1 起，得到 %llu", (unsigned long long)ids[0]);
        for (uint32_t i = 1; i < n; i++) {
            CHECK(ids[i] == ids[i - 1] + 1, "pkt_id 应严格递增 @%u", i);
            CHECK(ts[i] >= ts[i - 1], "时间单调 @%u", i);
        }
        for (uint32_t i = 0; i < n; i++) {
            CHECK(wire[i] >= cap[i], "wire_len>=cap_len @%u", i);
            CHECK(dir[i] == 1, "dir=出");
            CHECK(fids[i] != 0, "已归流");
            etap_span sp = etap_packet_bytes(b, i);
            CHECK(sp.data != NULL && sp.len > 0 && sp.len <= 128, "字节切片 @%u len=%u", i, sp.len);
            CHECK(sp.len <= cap[i], "拷贝长度不超过 cap_len");
            CHECK(sp.data[12] == 0x08 && sp.data[13] == 0x00, "EtherType IPv4");
            if (fl[i] & ETAP_RF_TRUNCATED)
                CHECK(cap[i] < wire[i], "截断包 cap<wire");
        }
    }

    CASE("解析视图与原始报文字节一致，缺失字段有 validity");
    {
        uint32_t nidx = 0, n = 0;
        const etap_parse_index_row *rows = etap_parse_index(b, &nidx);
        CHECK(rows && nidx == bh->n_parse_rows, "parse index");
        etap_type t;
        const uint16_t *sport = NULL, *dport = NULL;
        const uint32_t *src = NULL, *dst = NULL;
        const void *sni = NULL, *host = NULL;
        const uint8_t *sni_v = NULL, *host_v = NULL;
        const uint32_t *sni_off = NULL, *host_off = NULL;
        const uint64_t *pkt_ids = NULL;
        CHECK(etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_PKT_ID, &t, &n, (const void **)&pkt_ids, NULL, NULL) == ETAP_OK, "pkt ids");
        CHECK(etap_col(b, ETAP_SEC_PARSE_COLS, ETAP_FLD_TCP_SPORT, &t, &n, (const void **)&sport, NULL, NULL) == ETAP_OK, "sport");
        CHECK(etap_col(b, ETAP_SEC_PARSE_COLS, ETAP_FLD_TCP_DPORT, &t, &n, (const void **)&dport, NULL, NULL) == ETAP_OK, "dport");
        CHECK(etap_col(b, ETAP_SEC_PARSE_COLS, ETAP_FLD_IPV4_SRC, &t, &n, (const void **)&src, NULL, NULL) == ETAP_OK, "src");
        CHECK(etap_col(b, ETAP_SEC_PARSE_COLS, ETAP_FLD_IPV4_DST, &t, &n, (const void **)&dst, NULL, NULL) == ETAP_OK, "dst");
        CHECK(etap_col(b, ETAP_SEC_PARSE_COLS, ETAP_FLD_TLS_SNI, &t, &n, &sni, &sni_v, &sni_off) == ETAP_OK, "sni");
        CHECK(t == ETAP_T_BYTES && sni_off && sni_v, "sni 为变长列且带 validity");
        CHECK(etap_col(b, ETAP_SEC_PARSE_COLS, ETAP_FLD_HTTP_HOST, &t, &n, &host, &host_v, &host_off) == ETAP_OK, "host");
        int saw_sni = 0, saw_missing_sni = 0, saw_host = 0;
        for (uint32_t i = 0; i < nidx; i++) {
            /* 关联：解析行的 pkt_id 必须出现在报文视图 */
            int found = 0;
            uint32_t pidx = 0;
            for (uint32_t k = 0; k < bh->n_packets; k++)
                if (pkt_ids[k] == rows[i].pkt_id) { found = 1; pidx = k; break; }
            CHECK(found, "parse pkt_id %llu 能在报文视图找到", (unsigned long long)rows[i].pkt_id);
            etap_span sp = etap_packet_bytes(b, pidx);
            if (sp.len >= 38) {
                uint16_t ps = rd_u16be(sp.data + 34);
                uint16_t pd = rd_u16be(sp.data + 36);
                uint32_t is = rd_u32be(sp.data + 26);
                uint32_t id = rd_u32be(sp.data + 30);
                CHECK(sport[i] == ps, "sport 列(%u) 与报文字节(%u) 一致", sport[i], ps);
                CHECK(dport[i] == pd, "dport 列一致");
                CHECK(src[i] == is && dst[i] == id, "IP 列与字节一致");
            }
            int sni_ok = sni_v && (sni_v[i / 8] & (1u << (i % 8)));
            int host_ok = host_v && (host_v[i / 8] & (1u << (i % 8)));
            if (sni_ok) {
                saw_sni = 1;
                uint32_t a = sni_off[i], c = sni_off[i + 1];
                CHECK(c >= a, "sni offsets 有序");
                CHECK(c - a == 11 && memcmp((const uint8_t *)sni + a, "sni.example", 11) == 0,
                      "SNI 值");
            } else {
                saw_missing_sni = 1;
            }
            if (host_ok) {
                saw_host = 1;
                uint32_t a = host_off[i], c = host_off[i + 1];
                CHECK(c > a && memcmp((const uint8_t *)host + a, "example.com", c - a) == 0, "Host 值");
            }
            CHECK(rows[i].proto_id == ETAP_PROTO_HTTP || rows[i].proto_id == ETAP_PROTO_TLS,
                  "proto_id 应为编号而非字符串");
        }
        CHECK(saw_sni, "本批应出现有效 SNI");
        CHECK(saw_missing_sni, "本批应出现 SNI 缺失（validity=0），不得用空串冒充");
        CHECK(saw_host, "本批应出现 HTTP Host");
    }

    CASE("流视图通过 flow_id / pkt_id 与报文关联");
    {
        uint32_t nf = 0, n = 0;
        const etap_flow_meta_row *fr = etap_flow_meta(b, &nf);
        CHECK(fr && nf == bh->n_flows, "flow meta");
        etap_type t;
        const uint64_t *fids = NULL, *pkt_ids = NULL;
        const uint64_t *pkts_fwd = NULL, *bytes_fwd = NULL;
        CHECK(etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_FLOW_ID, &t, &n, (const void **)&fids, NULL, NULL) == ETAP_OK, "");
        CHECK(etap_col(b, ETAP_SEC_PACKET_META, ETAP_COL_PKT_ID, &t, &n, (const void **)&pkt_ids, NULL, NULL) == ETAP_OK, "");
        CHECK(etap_col(b, ETAP_SEC_FLOW_FEAT, ETAP_FEAT_PKTS_FWD, &t, &nf, (const void **)&pkts_fwd, NULL, NULL) == ETAP_OK, "pkts_fwd");
        CHECK(etap_col(b, ETAP_SEC_FLOW_FEAT, ETAP_FEAT_BYTES_FWD, &t, &nf, (const void **)&bytes_fwd, NULL, NULL) == ETAP_OK, "bytes_fwd");
        for (uint32_t i = 0; i < nf; i++) {
            uint32_t cnt = 0;
            uint64_t min_id = UINT64_MAX, max_id = 0;
            for (uint32_t k = 0; k < bh->n_packets; k++) {
                if (fids[k] == fr[i].flow_id) {
                    cnt++;
                    if (pkt_ids[k] < min_id) min_id = pkt_ids[k];
                    if (pkt_ids[k] > max_id) max_id = pkt_ids[k];
                }
            }
            CHECK(cnt > 0, "流 %llu 在本批至少有一个报文", (unsigned long long)fr[i].flow_id);
            CHECK(fr[i].pkt_id_last == max_id, "pkt_id_last 应对应本批最后一包");
            CHECK(fr[i].start_ns <= fr[i].last_ns, "流时间有序");
            CHECK(pkts_fwd[i] >= cnt, "累计 pkts_fwd 不少于本批计数");
            CHECK(bytes_fwd[i] >= pkts_fwd[i], "字节数至少覆盖包数的粗下界");
            CHECK(fr[i].event == 1 || fr[i].event == 2, "New 或 Update");
        }
        CHECK(section_present(b, ETAP_SEC_FLOW_PKTS), "含流到报文的索引节");
    }

    uint32_t first_schema = bh->schema_id;
    CHECK(etap_release(b) == ETAP_OK, "release");
    b = NULL;

    CASE("批次序号递增，且数据通路不含 JSON");
    {
        CHECK(etap_poll(sub, 0, &b) == ETAP_OK, "第二批");
        const etap_batch_hdr *h2 = etap_batch_header(b);
        CHECK(h2->seq == 1, "seq=1 得到 %llu", (unsigned long long)h2->seq);
        CHECK(h2->schema_id == first_schema, "schema 保持");
        CHECK((h2->flags & ETAP_BF_SCHEMA_EMBEDDED) == 0, "同 schema 不再内嵌");
        uint32_t sz = 0;
        const uint8_t *p = etap_batch_data(b, &sz);
        /* 不把批次当成文本；抽查不应出现 JSON 对象包装 */
        int saw_json = 0;
        for (uint32_t i = 0; i + 8 < sz; i++) {
            if (p[i] == '{' && memcmp(p + i, "{\"pkt\"", 6) == 0) saw_json = 1;
        }
        CHECK(!saw_json, "批次中不应出现 JSON 包装");
        etap_release(b);
        b = NULL;
    }

    CASE("按需订阅：不取原始字节、不取解析时节段省略");
    {
        uint8_t buf2[512];
        uint32_t ln = 0;
        uint32_t f3[] = { ETAP_FLD_TCP_SPORT, ETAP_FLD_TCP_DPORT };
        build_full_req(buf2, &ln, ETAP_VIEW_PACKET, 4,
                       ETAP_META_PKT_ID | ETAP_META_TS_NS | ETAP_META_WIRE_LEN,
                       ETAP_BYTES_NONE, 0, f3, 2, NULL, 0, 0);
        /* view is packet only — parse/flow offs still present but view_mask restricts */
        etap_sub_req r2 = { buf2, ln };
        /* new connection so we don't disturb the first sub? can use same conn, new sub */
        etap_conn *c2 = NULL;
        etap_open("etap://sim", NULL, &c2);
        etap_sub *s2 = NULL;
        CHECK(etap_subscribe(c2, &r2, &s2) == ETAP_OK, "瘦订阅");
        etap_batch *b2 = NULL;
        CHECK(etap_poll(s2, 0, &b2) == ETAP_OK, "poll 瘦批次");
        const etap_batch_hdr *h = etap_batch_header(b2);
        CHECK(h->n_packets > 0, "仍有报文元数据");
        CHECK(h->n_parse_rows == 0 && h->n_flows == 0, "未订阅的视图为空");
        CHECK(!section_present(b2, ETAP_SEC_PACKET_BYTES), "无 PACKET_BYTES");
        CHECK(!section_present(b2, ETAP_SEC_PARSE_COLS), "无 PARSE_COLS");
        CHECK(!section_present(b2, ETAP_SEC_FLOW_META), "无 FLOW_META");
        CHECK(col_present(b2, ETAP_SEC_PACKET_META, ETAP_COL_PKT_ID), "有 pkt_id");
        CHECK(col_present(b2, ETAP_SEC_PACKET_META, ETAP_COL_TS_NS), "有 ts");
        CHECK(col_present(b2, ETAP_SEC_PACKET_META, ETAP_COL_WIRE_LEN), "有 wire_len");
        CHECK(!col_present(b2, ETAP_SEC_PACKET_META, ETAP_COL_DIR), "未订阅 dir");
        CHECK(!col_present(b2, ETAP_SEC_PACKET_META, ETAP_COL_FLOW_ID), "未订阅 flow_id");
        etap_span sp = etap_packet_bytes(b2, 0);
        CHECK(sp.data == NULL && sp.len == 0, "没有字节切片");
        etap_release(b2);
        etap_unsubscribe(s2);
        etap_close(c2);
    }

    CASE("消费变慢时报告缺口，pkt_id 跳号，不得当成未发生");
    {
        uint32_t queued = 0;
        CHECK(etap_sim_fill_ring(sub, &queued) == ETAP_OK, "填满环");
        CHECK(queued >= 1, "至少入队一批，queued=%u", queued);
        CHECK(etap_sim_drop(sub, 193, 193ull * 100) == ETAP_OK, "注入缺口");
        /* 先排空已在环上、可能尚无缺口标记的批次 */
        int saw_gap = 0;
        uint64_t gap_pkts = 0, last_id = 0, first_after = 0;
        for (int i = 0; i < 16; i++) {
            etap_batch *bx = NULL;
            if (etap_poll(sub, 0, &bx) != ETAP_OK) break;
            const etap_batch_hdr *h = etap_batch_header(bx);
            etap_type t; uint32_t n = 0; const uint64_t *ids = NULL;
            etap_col(bx, ETAP_SEC_PACKET_META, ETAP_COL_PKT_ID, &t, &n, (const void **)&ids, NULL, NULL);
            if (h->flags & ETAP_BF_HAS_GAP) {
                saw_gap = 1;
                gap_pkts = h->gap_dropped_pkts;
                CHECK(h->gap_dropped_pkts == 193, "gap_dropped_pkts=%llu", (unsigned long long)h->gap_dropped_pkts);
                CHECK((h->flags & ETAP_BF_OVERFLOW) != 0, "OVERFLOW 标记");
                CHECK(h->gap_first_pkt_id != 0 && h->gap_last_pkt_id >= h->gap_first_pkt_id, "缺口区间");
                if (n) first_after = ids[0];
                if (last_id && n)
                    CHECK(ids[0] > last_id + 1, "缺口后 pkt_id 必须跳号");
            }
            if (n) last_id = ids[n - 1];
            etap_release(bx);
            if (saw_gap) break;
        }
        CHECK(saw_gap, "释放积压后应看到带 HAS_GAP 的批次");
        CHECK(gap_pkts == 193, "缺口计数应到达模型侧");
        (void)first_after;
        etap_sub_stats st;
        CHECK(etap_stats(sub, &st) == ETAP_OK, "stats");
        CHECK(st.dropped_pkts >= 193, "stats.dropped_pkts");
    }

    CASE("截断标记：cap_len < wire_len 时 TRUNCATED 置位");
    {
        int ok = 0;
        for (int i = 0; i < 20 && !ok; i++) {
            etap_batch *bx = NULL;
            if (etap_poll(sub, 0, &bx) != ETAP_OK) break;
            etap_type t; uint32_t n = 0;
            const uint32_t *wire = NULL, *cap = NULL;
            const uint16_t *fl = NULL;
            etap_col(bx, ETAP_SEC_PACKET_META, ETAP_COL_WIRE_LEN, &t, &n, (const void **)&wire, NULL, NULL);
            etap_col(bx, ETAP_SEC_PACKET_META, ETAP_COL_CAP_LEN, &t, &n, (const void **)&cap, NULL, NULL);
            etap_col(bx, ETAP_SEC_PACKET_META, ETAP_COL_FLAGS, &t, &n, (const void **)&fl, NULL, NULL);
            for (uint32_t k = 0; k < n; k++) {
                if (cap[k] < wire[k]) {
                    CHECK(fl[k] & ETAP_RF_TRUNCATED, "截断包必须置 TRUNCATED");
                    ok = 1;
                }
            }
            if (etap_batch_header(bx)->flags & ETAP_BF_TRUNCATED)
                CHECK(ok, "批次 TRUNCATED 时至少一行被截断");
            etap_release(bx);
        }
        CHECK(ok, "应能观察到截断报文");
    }

    CASE("有限生产结束后 poll 返回 EMPTY");
    {
        etap_conn *c3 = NULL;
        etap_open("etap://sim", NULL, &c3);
        etap_sub *s3 = NULL;
        etap_subscribe(c3, &req, &s3);
        CHECK(etap_sim_set_limit(s3, 5) == ETAP_OK, "limit=5");
        uint32_t got = 0;
        for (;;) {
            etap_batch *bx = NULL;
            etap_status st = etap_poll(s3, 0, &bx);
            if (st == ETAP_EMPTY) break;
            CHECK(st == ETAP_OK, "limit 内应为 OK");
            got += etap_batch_header(bx)->n_packets;
            etap_release(bx);
            if (got > 16) { CHECK(0, "未在合理范围内结束"); break; }
        }
        CHECK(got == 5, "恰好 5 个报文，得到 %u", got);
        etap_batch *bx = NULL;
        CHECK(etap_poll(s3, 0, &bx) == ETAP_EMPTY && bx == NULL, "再次 poll 仍为 EMPTY");
        etap_unsubscribe(s3);
        etap_close(c3);
    }

    CASE("调整订阅后 schema_id 变化；破坏性变更提升 epoch");
    {
        uint32_t schema0, epoch0;
        etap_sub_stats st;
        etap_stats(sub, &st);
        schema0 = st.schema_id;
        epoch0 = st.epoch;
        uint8_t buf2[512];
        uint32_t ln = 0;
        uint32_t f1[] = { ETAP_FLD_TCP_DPORT };
        build_full_req(buf2, &ln, ETAP_VIEW_PACKET | ETAP_VIEW_PARSE, 4,
                       ETAP_META_PKT_ID | ETAP_META_TS_NS,
                       ETAP_BYTES_HEADERS, 54, f1, 1, all_feats, 5, 1 /* destructive */);
        etap_sub_req r2 = { buf2, ln };
        CHECK(etap_resubscribe(sub, &r2) == ETAP_OK, "resubscribe");
        etap_stats(sub, &st);
        CHECK(st.schema_id != schema0, "schema_id 应变 %u -> %u", schema0, st.schema_id);
        CHECK(st.epoch == epoch0 + 1, "破坏性订阅 epoch+1，得到 %u", st.epoch);
        etap_batch *bx = NULL;
        CHECK(etap_poll(sub, 0, &bx) == ETAP_OK, "新世代批次");
        const etap_batch_hdr *h = etap_batch_header(bx);
        CHECK(h->epoch == st.epoch && h->schema_id == st.schema_id, "批次标识与订阅一致");
        CHECK((h->flags & ETAP_BF_SCHEMA_EMBEDDED) != 0, "新 schema 应内嵌");
        etap_type t; uint32_t n = 0; const void *d = NULL;
        CHECK(etap_col(bx, ETAP_SEC_PACKET_META, ETAP_COL_PKT_ID, &t, &n, &d, NULL, NULL) == ETAP_OK, "仍有 pkt_id");
        CHECK(!col_present(bx, ETAP_SEC_PACKET_META, ETAP_COL_DIR), "新订阅不含 dir");
        CHECK(etap_col(bx, ETAP_SEC_PARSE_COLS, ETAP_FLD_TCP_SPORT, &t, &n, &d, NULL, NULL) == ETAP_INVALID,
              "未订阅的 sport 不得出现");
        CHECK(col_present(bx, ETAP_SEC_PARSE_COLS, ETAP_FLD_TCP_DPORT), "应有 dport");
        /* 破坏性变更后 pkt_id 从 1 重新计数 */
        const uint64_t *ids = (const uint64_t *)d;
        /* d was last failed or dport; fetch pkt_id again */
        etap_col(bx, ETAP_SEC_PACKET_META, ETAP_COL_PKT_ID, &t, &n, (const void **)&ids, NULL, NULL);
        CHECK(ids[0] == 1, "新 epoch 的 pkt_id 从 1 开始，得到 %llu", (unsigned long long)ids[0]);
        etap_release(bx);
    }

    CASE("release 之后槽位可再次交付；关闭后不可用");
    {
        etap_batch *bx = NULL;
        CHECK(etap_poll(sub, 0, &bx) == ETAP_OK, "再取一批");
        CHECK(etap_release(bx) == ETAP_OK, "release");
        CHECK(etap_unsubscribe(sub) == ETAP_OK, "unsubscribe");
        /* sub 已释放，不能再使用 */
        CHECK(etap_close(conn) == ETAP_OK, "close");
    }


    CASE("PACKET_BYTES 紧密拼接，无每包 8 字节填充");
    {
        etap_conn *c4 = NULL;
        etap_open("etap://sim", NULL, &c4);
        etap_sub *s4 = NULL;
        CHECK(etap_subscribe(c4, &req, &s4) == ETAP_OK, "subscribe");
        etap_batch *b4 = NULL;
        CHECK(etap_poll(s4, 0, &b4) == ETAP_OK && b4, "poll");
        const etap_batch_hdr *h4 = etap_batch_header(b4);
        etap_type t;
        uint32_t n = 0;
        const uint32_t *off = NULL, *len = NULL;
        CHECK(etap_col(b4, ETAP_SEC_PACKET_META, ETAP_COL_BYTES_OFF, &t, &n, (const void **)&off, NULL, NULL) == ETAP_OK, "bytes_off");
        CHECK(etap_col(b4, ETAP_SEC_PACKET_META, ETAP_COL_BYTES_LEN, &t, &n, (const void **)&len, NULL, NULL) == ETAP_OK, "bytes_len");
        CHECK(n == h4->n_packets && n >= 2, "至少两包以便检查相邻偏移 n=%u", n);
        for (uint32_t i = 0; i + 1 < n; i++) {
            CHECK(off[i] + len[i] == off[i + 1],
                  "切片应紧密相邻 @%u off=%u len=%u next=%u", i, off[i], len[i], off[i + 1]);
        }
        for (uint32_t i = 0; i < n; i++) {
            etap_span sp = etap_packet_bytes(b4, i);
            CHECK(sp.len == len[i], "etap_packet_bytes 长度与列一致 @%u", i);
        }

        CASE("值往返：pkt_id / ts_ns / wire_len / proto / 端口 / flow_id");
        {
            const uint64_t *ids = NULL, *fids = NULL, *ts = NULL;
            const uint32_t *wire = NULL;
            CHECK(etap_col(b4, ETAP_SEC_PACKET_META, ETAP_COL_PKT_ID, &t, &n, (const void **)&ids, NULL, NULL) == ETAP_OK, "pkt_id");
            CHECK(etap_col(b4, ETAP_SEC_PACKET_META, ETAP_COL_FLOW_ID, &t, &n, (const void **)&fids, NULL, NULL) == ETAP_OK, "flow_id");
            CHECK(etap_col(b4, ETAP_SEC_PACKET_META, ETAP_COL_TS_NS, &t, &n, (const void **)&ts, NULL, NULL) == ETAP_OK, "ts");
            CHECK(etap_col(b4, ETAP_SEC_PACKET_META, ETAP_COL_WIRE_LEN, &t, &n, (const void **)&wire, NULL, NULL) == ETAP_OK, "wire");
            /* Simulator logical clock: T0=1e12 ns, IAT=1 ms, pkt_id from 1. */
            const uint64_t t0 = 1000000000000ull;
            const uint64_t iat = 1000000ull;
            CHECK(ids[0] == 1 && ts[0] == t0, "首包 pkt_id=1 ts=T0，得到 id=%llu ts=%llu",
                  (unsigned long long)ids[0], (unsigned long long)ts[0]);
            for (uint32_t i = 0; i < n; i++) {
                CHECK(ids[i] == 1ull + i, "pkt_id 逻辑值 @%u", i);
                CHECK(ts[i] == t0 + i * iat, "ts_ns 逻辑值 @%u", i);
                CHECK(fids[i] != 0, "已归流 @%u", i);
                CHECK(wire[i] >= 54, "wire_len 至少以太网头+IP+TCP @%u %u", i, wire[i]);
            }
            CHECK(h4->time_first_ns == ts[0] && h4->time_last_ns == ts[n - 1], "批次时间窗与列一致");
            uint32_t nidx = 0;
            const etap_parse_index_row *rows = etap_parse_index(b4, &nidx);
            const uint16_t *sport = NULL, *dport = NULL;
            CHECK(rows && nidx == n, "parse index 行数");
            CHECK(etap_col(b4, ETAP_SEC_PARSE_COLS, ETAP_FLD_TCP_SPORT, &t, &n, (const void **)&sport, NULL, NULL) == ETAP_OK, "sport");
            CHECK(etap_col(b4, ETAP_SEC_PARSE_COLS, ETAP_FLD_TCP_DPORT, &t, &n, (const void **)&dport, NULL, NULL) == ETAP_OK, "dport");
            for (uint32_t i = 0; i < nidx; i++) {
                CHECK(rows[i].pkt_id == ids[i], "parse pkt_id 往返 @%u", i);
                CHECK(rows[i].proto_id == ETAP_PROTO_HTTP || rows[i].proto_id == ETAP_PROTO_TLS, "proto_id");
                if (dport[i] == 80)
                    CHECK(rows[i].proto_id == ETAP_PROTO_HTTP && sport[i] == 49152, "HTTP 流端口");
                else if (dport[i] == 443)
                    CHECK(rows[i].proto_id == ETAP_PROTO_TLS && (sport[i] == 49153 || sport[i] == 49154), "TLS 流端口");
            }
            uint32_t nf = 0;
            const etap_flow_meta_row *fr = etap_flow_meta(b4, &nf);
            CHECK(fr && nf == h4->n_flows && nf > 0, "flow meta");
            for (uint32_t i = 0; i < nf; i++) {
                int seen = 0;
                for (uint32_t k = 0; k < n; k++)
                    if (fids[k] == fr[i].flow_id) seen = 1;
                CHECK(seen, "flow_id %llu 能在报文列中找到", (unsigned long long)fr[i].flow_id);
            }
        }

        CASE("紧凑批次体积严格小于同等内容的 v0.1 布局");
        {
            uint32_t v01 = v01_equivalent_size(b4);
            CHECK(h4->total_size < v01,
                  "v0.2 total_size=%u 应小于 v0.1 等价 %u（打包不得是空操作）",
                  h4->total_size, v01);
            /* Also require packed pkt_id/ts to beat n*8, and no 8-byte packet padding. */
            uint32_t pad_bytes = 0, tight_bytes = 0;
            for (uint32_t i = 0; i < n; i++) {
                tight_bytes += len[i];
                pad_bytes += align8_u(len[i]);
            }
            CHECK(tight_bytes < pad_bytes || n == 0,
                  "去掉每包 8 字节填充后字节堆应更小 tight=%u padded=%u", tight_bytes, pad_bytes);
            /* Inspect raw pkt_id column payload: DELTA/FOR/CONST must be < n*8. */
            etap_section meta;
            int got_meta = 0;
            for (uint16_t i = 0; i < h4->n_sections; i++) {
                if (etap_batch_section(b4, i, &meta) == ETAP_OK && meta.kind == ETAP_SEC_PACKET_META) {
                    got_meta = 1;
                    break;
                }
            }
            CHECK(got_meta, "PACKET_META 节");
            const uint8_t *rawb = etap_batch_data(b4, NULL);
            const uint8_t *base = rawb + meta.off;
            uint16_t ncols = 0;
            memcpy(&ncols, base, 2);
            int saw_small = 0;
            for (uint16_t i = 0; i < ncols; i++) {
                etap_col_desc d;
                memcpy(&d, base + 4 + 16u * i, 16);
                if (d.col_id == ETAP_COL_PKT_ID || d.col_id == ETAP_COL_TS_NS) {
                    CHECK(d.codec != ETAP_CODEC_RAW,
                          "col %u 应对单调 u64 使用压缩编码，codec=%u", d.col_id, d.codec);
                    CHECK(d.data_len < n * 8u,
                          "col %u packed data_len=%u 应小于 n*8=%u", d.col_id, d.data_len, n * 8u);
                    saw_small = 1;
                }
            }
            CHECK(saw_small, "应检查到已压缩的 pkt_id/ts 列");
            printf("    例：本批 total_size=%u，v0.1 等价=%u，n_packets=%u\n",
                   h4->total_size, v01, h4->n_packets);
        }

        CASE("HAS_GAP 时头为 124 字节且含缺口块；无缺口时为 92 且不含该块");
        {
            CHECK(h4->hdr_len == 92 && h4->sections_off == 92, "无缺口 hdr_len/sections_off");
            /* The bytes immediately after the 92-byte prefix are the section directory,
             * not a 32-byte zero gap block written onto the wire. */
            const uint8_t *rawb = etap_batch_data(b4, NULL);
            etap_section s0;
            CHECK(etap_batch_section(b4, 0, &s0) == ETAP_OK, "第一节");
            CHECK(memcmp(rawb + 92, &s0, ETAP_SECTION_LEN) == 0,
                  "偏移 92 处应为节目录而非 gap 块");
            etap_release(b4);
            b4 = NULL;
            CHECK(etap_sim_drop(s4, 7, 700) == ETAP_OK, "注入缺口");
            CHECK(etap_poll(s4, 0, &b4) == ETAP_OK && b4, "缺口后批次");
            const etap_batch_hdr *hg = etap_batch_header(b4);
            CHECK((hg->flags & ETAP_BF_HAS_GAP) != 0, "HAS_GAP");
            CHECK(hg->hdr_len == 124 && hg->sections_off == 124, "有缺口时 hdr_len=124，得到 %u", hg->hdr_len);
            CHECK(hg->gap_dropped_pkts == 7, "gap_dropped_pkts=%llu", (unsigned long long)hg->gap_dropped_pkts);
            CHECK(hg->gap_dropped_bytes == 700, "gap_dropped_bytes");
            CHECK(hg->gap_first_pkt_id != 0 && hg->gap_last_pkt_id >= hg->gap_first_pkt_id, "缺口区间");
            uint32_t rawg = 0;
            const uint8_t *rg = etap_batch_data(b4, &rawg);
            uint64_t raw_gap_pkts = 0, raw_gap_bytes = 0;
            memcpy(&raw_gap_pkts, rg + 92, 8);
            memcpy(&raw_gap_bytes, rg + 100, 8);
            CHECK(raw_gap_pkts == 7 && raw_gap_bytes == 700, "线上 gap 块出现在偏移 92 且非零");
            etap_section sg;
            CHECK(etap_batch_section(b4, 0, &sg) == ETAP_OK, "有缺口时节目录在 124");
            CHECK(memcmp(rg + 124, &sg, ETAP_SECTION_LEN) == 0, "节目录紧随 124 字节头");
            etap_release(b4);
        }
        etap_unsubscribe(s4);
        etap_close(c4);
    }

    CASE("头文件结构体大小");
    {
        CHECK(sizeof(etap_batch_hdr) == 124, "decoded batch hdr（含 gap 字段）");
        CHECK(sizeof(etap_section) == 14, "packed section");
        CHECK(sizeof(etap_col_desc) == 16, "col desc");
        CHECK(sizeof(etap_parse_index_row) == 26, "parse row");
        CHECK(sizeof(etap_flow_meta_row) == 48, "flow row");
        CHECK(sizeof(etap_frame_hdr) == 16, "frame hdr");
    }

    finish_case();
    printf("\n合计：%d 通过，%d 失败\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
