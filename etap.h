/* ETAP v0.1 — Ethernet Traffic Awareness Port
 * Machine-facing binary API. The data path does not use JSON or text logs.
 */
#ifndef ETAP_H
#define ETAP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETAP_VERSION        0x0001u
#define ETAP_MAGIC          0x31504154u  /* "TAP1" little-endian */
#define ETAP_BATCH_HDR_LEN  128u

typedef enum etap_status {
    ETAP_OK            = 0,
    ETAP_EMPTY         = 1,
    ETAP_TIMEOUT       = 2,
    ETAP_UNSUPPORTED   = 3,
    ETAP_INVALID       = 4,
    ETAP_REDUCED       = 5,
    ETAP_STALE_EPOCH   = 6,
    ETAP_NOMEM         = 7,
    ETAP_IO            = 8,
    ETAP_CLOSED        = 9,
    ETAP_SCHEMA        = 10
} etap_status;

typedef enum etap_type {
    ETAP_T_U8     = 1,
    ETAP_T_U16    = 2,
    ETAP_T_U32    = 3,
    ETAP_T_U64    = 4,
    ETAP_T_I8     = 5,
    ETAP_T_I16    = 6,
    ETAP_T_I32    = 7,
    ETAP_T_I64    = 8,
    ETAP_T_BOOL   = 9,
    ETAP_T_F32    = 10,
    ETAP_T_F64    = 11,
    ETAP_T_MAC    = 12,
    ETAP_T_IPV4   = 13,
    ETAP_T_IPV6   = 14,
    ETAP_T_ENUM   = 15,
    ETAP_T_BYTES  = 16,
    ETAP_T_TS_NS  = 17,
    ETAP_T_DUR_NS = 18
} etap_type;

enum {
    ETAP_VIEW_PACKET = 1u << 0,
    ETAP_VIEW_PARSE  = 1u << 1,
    ETAP_VIEW_FLOW   = 1u << 2
};

enum {
    ETAP_CAP_SHM        = 1u << 0,
    ETAP_CAP_REMOTE     = 1u << 1,
    ETAP_CAP_ZEROCOPY   = 1u << 2,
    ETAP_CAP_SAMPLE     = 1u << 3,
    ETAP_CAP_AGGREGATE  = 1u << 4,
    ETAP_CAP_BPF        = 1u << 5,
    ETAP_CAP_STRUCT_FLT = 1u << 6,
    ETAP_CAP_RDMA       = 1u << 7
};

enum {
    ETAP_OVERFLOW_SAMPLE    = 0,
    ETAP_OVERFLOW_AGGREGATE = 1,
    ETAP_OVERFLOW_DROP      = 2
};

enum {
    ETAP_SAMPLE_NONE     = 0,
    ETAP_SAMPLE_HASH     = 1,
    ETAP_SAMPLE_FIRST_K  = 2,
    ETAP_SAMPLE_1_IN_N   = 3,
    ETAP_SAMPLE_TOKEN    = 4
};

enum {
    ETAP_BYTES_NONE    = 0,
    ETAP_BYTES_HEADERS = 1,
    ETAP_BYTES_RANGES  = 2,
    ETAP_BYTES_PREFIX  = 3,
    ETAP_BYTES_CAP     = 4
};

/* Packet meta col_id */
enum {
    ETAP_COL_PKT_ID     = 1,
    ETAP_COL_FLOW_ID    = 2,
    ETAP_COL_TS_NS      = 3,
    ETAP_COL_WIRE_LEN   = 4,
    ETAP_COL_CAP_LEN    = 5,
    ETAP_COL_DIR        = 6,
    ETAP_COL_IFINDEX    = 7,
    ETAP_COL_FLAGS      = 8,
    ETAP_COL_L3_OFF     = 9,
    ETAP_COL_L4_OFF     = 10,
    ETAP_COL_BYTES_OFF  = 11,
    ETAP_COL_BYTES_LEN  = 12
};
#define ETAP_COL_BYTES ETAP_COL_BYTES_OFF

/* Well-known catalog IDs used by the reference implementation. */
#define ETAP_PROTO_ETH   1u
#define ETAP_PROTO_IPV4  2u
#define ETAP_PROTO_TCP   3u
#define ETAP_PROTO_TLS   4u
#define ETAP_PROTO_HTTP  5u

#define ETAP_FLD_IPV4_SRC   1u
#define ETAP_FLD_IPV4_DST   2u
#define ETAP_FLD_TCP_SPORT  3u
#define ETAP_FLD_TCP_DPORT  4u
#define ETAP_FLD_TLS_SNI    5u
#define ETAP_FLD_HTTP_HOST  6u

#define ETAP_FEAT_PKTS_FWD  1u
#define ETAP_FEAT_PKTS_REV  2u
#define ETAP_FEAT_BYTES_FWD 3u
#define ETAP_FEAT_BYTES_REV 4u
#define ETAP_FEAT_DURATION  5u

enum {
    ETAP_META_PKT_ID    = 1u << 0,
    ETAP_META_FLOW_ID   = 1u << 1,
    ETAP_META_TS_NS     = 1u << 2,
    ETAP_META_WIRE_LEN  = 1u << 3,
    ETAP_META_CAP_LEN   = 1u << 4,
    ETAP_META_DIR       = 1u << 5,
    ETAP_META_IFINDEX   = 1u << 6,
    ETAP_META_FLAGS     = 1u << 7,
    ETAP_META_L3_OFF    = 1u << 8,
    ETAP_META_L4_OFF    = 1u << 9,
    ETAP_META_PAYLOAD   = 1u << 10
};

enum {
    ETAP_FLOW_EV_NEW      = 1u << 0,
    ETAP_FLOW_EV_UPDATE   = 1u << 1,
    ETAP_FLOW_EV_EXPIRE   = 1u << 2,
    ETAP_FLOW_EV_RESET    = 1u << 3,
    ETAP_FLOW_EV_ANOMALY  = 1u << 4
};

enum {
    ETAP_SEC_PACKET_META  = 1,
    ETAP_SEC_PACKET_BYTES = 2,
    ETAP_SEC_PARSE_INDEX  = 3,
    ETAP_SEC_PARSE_COLS   = 4,
    ETAP_SEC_FLOW_META    = 5,
    ETAP_SEC_FLOW_FEAT    = 6,
    ETAP_SEC_FLOW_PKTS    = 7,
    ETAP_SEC_SCHEMA       = 8,
    ETAP_SEC_HEAP         = 9,
    ETAP_SEC_GAP          = 10
};

enum {
    ETAP_BF_HAS_GAP          = 1u << 0,
    ETAP_BF_SAMPLED          = 1u << 1,
    ETAP_BF_AGGREGATED       = 1u << 2,
    ETAP_BF_TRUNCATED        = 1u << 3,
    ETAP_BF_SCHEMA_EMBEDDED  = 1u << 4,
    ETAP_BF_CLOCK_DISCONT    = 1u << 5,
    ETAP_BF_OVERFLOW         = 1u << 6,
    ETAP_BF_END_OF_EPOCH     = 1u << 7
};

enum {
    ETAP_RF_SAMPLED          = 1u << 0,
    ETAP_RF_TRUNCATED        = 1u << 1,
    ETAP_RF_GAP_BEFORE       = 1u << 2,
    ETAP_RF_MISSING_DEP      = 1u << 3,
    ETAP_RF_PARSE_INCOMPLETE = 1u << 4,
    ETAP_RF_PARSE_ERROR      = 1u << 5,
    ETAP_RF_AGGREGATED       = 1u << 6,
    ETAP_RF_CSUM_ERR         = 1u << 7
};

enum {
    ETAP_FRM_DISCOVER_REQ    = 1,
    ETAP_FRM_DISCOVER_RSP    = 2,
    ETAP_FRM_SUBSCRIBE_REQ   = 3,
    ETAP_FRM_SUBSCRIBE_RSP   = 4,
    ETAP_FRM_RESUBSCRIBE_REQ = 5,
    ETAP_FRM_UNSUBSCRIBE_REQ = 6,
    ETAP_FRM_OK              = 7,
    ETAP_FRM_ERROR           = 8,
    ETAP_FRM_BATCH           = 9,
    ETAP_FRM_ACK             = 10,
    ETAP_FRM_STATS_REQ       = 11,
    ETAP_FRM_STATS_RSP       = 12,
    ETAP_FRM_HEARTBEAT       = 13
};

#pragma pack(push, 1)

typedef struct etap_span {
    const uint8_t *data;
    uint32_t       len;
} etap_span;

typedef struct etap_open_opt {
    uint32_t timeout_ms;
    uint32_t flags;
} etap_open_opt;

typedef struct etap_caps_hdr {
    uint32_t magic;
    uint16_t version;
    uint16_t hdr_len;
    uint32_t flags;
    uint32_t port_id;
    uint8_t  clock;
    uint8_t  endian;
    uint16_t reserved0;
    uint32_t max_batch_records;
    uint32_t max_batch_bytes;
    uint32_t min_wait_us;
    uint32_t max_wait_us;
    uint32_t max_slice;
    uint32_t view_mask;
    uint16_t n_protos;
    uint16_t n_fields;
    uint16_t n_features;
    uint16_t reserved1;
    uint32_t protos_off;
    uint32_t fields_off;
    uint32_t features_off;
    uint32_t strtab_off;
    uint32_t strtab_len;
    uint32_t time_res_ns;
    uint32_t snaplen_max;
} etap_caps_hdr;

typedef struct etap_proto_desc {
    uint32_t proto_id;
    uint32_t parent_id;
    uint32_t name_off;
    uint16_t name_len;
    uint16_t flags;
} etap_proto_desc;

typedef struct etap_field_desc {
    uint32_t field_id;
    uint32_t proto_id;
    uint16_t type;
    uint16_t flags;
    uint32_t name_off;
    uint16_t name_len;
    uint16_t reserved;
} etap_field_desc;

typedef struct etap_byte_range {
    uint16_t off;
    uint16_t len;
} etap_byte_range;

typedef struct etap_sub_req_hdr {
    uint32_t req_len;
    uint32_t flags;
    uint32_t view_mask;
    uint32_t max_records;
    uint32_t max_bytes;
    uint32_t max_wait_us;
    uint32_t budget_rps;
    uint64_t budget_bps;
    uint8_t  overflow;
    uint8_t  sample_mode;
    uint16_t reserved;
    uint32_t sample_n;
    uint32_t sample_k;
    uint32_t filter_off;
    uint32_t filter_len;
    uint32_t packet_off;
    uint32_t parse_off;
    uint32_t flow_off;
} etap_sub_req_hdr;

typedef struct etap_packet_sel_hdr {
    uint32_t meta_mask;
    uint8_t  bytes_mode;
    uint8_t  n_ranges;
    uint16_t reserved;
    uint16_t max_bytes;
} etap_packet_sel_hdr;

typedef struct etap_sub_ack {
    uint64_t sub_id;
    uint32_t epoch;
    uint32_t schema_id;
    uint32_t granted_flags;
    uint32_t effective_max_records;
    uint32_t effective_max_bytes;
    uint32_t effective_max_wait_us;
} etap_sub_ack;

typedef struct etap_batch_hdr {
    uint32_t magic;
    uint16_t version;
    uint16_t hdr_len;
    uint32_t flags;
    uint16_t n_sections;
    uint8_t  clock;
    uint8_t  reserved0;
    uint64_t batch_id;
    uint64_t sub_id;
    uint32_t epoch;
    uint32_t schema_id;
    uint64_t seq;
    uint64_t time_first_ns;
    uint64_t time_last_ns;
    uint32_t n_packets;
    uint32_t n_parse_rows;
    uint32_t n_flows;
    uint32_t reserved1;
    uint64_t gap_dropped_pkts;
    uint64_t gap_dropped_bytes;
    uint64_t gap_first_pkt_id;
    uint64_t gap_last_pkt_id;
    uint32_t producer_lag_us;
    uint32_t crc32c;
    uint32_t sections_off;
    uint32_t total_size;
} etap_batch_hdr;

typedef struct etap_section {
    uint16_t kind;
    uint16_t flags;
    uint32_t count;
    uint64_t off;
    uint64_t size;
} etap_section;

typedef struct etap_col_desc {
    uint32_t col_id;
    uint16_t type;
    uint16_t flags;
    uint32_t data_off;
    uint32_t data_len;
} etap_col_desc;

typedef struct etap_parse_index_row {
    uint64_t pkt_id;
    uint64_t msg_id;
    uint32_t proto_id;
    uint16_t msg_off;
    uint16_t msg_len;
    uint16_t flags;
    uint16_t reserved;
    uint32_t reserved2; /* pad to 32-byte row */
} etap_parse_index_row;

typedef struct etap_flow_meta_row {
    uint64_t flow_id;
    uint8_t  event;
    uint8_t  state;
    uint16_t flags;
    uint32_t ifindex;
    uint64_t start_ns;
    uint64_t last_ns;
    uint64_t pkt_id_first;
    uint64_t pkt_id_last;
} etap_flow_meta_row;

typedef struct etap_frame_hdr {
    uint32_t len;
    uint16_t type;
    uint16_t flags;
    uint64_t corr_id;
} etap_frame_hdr;

typedef struct etap_ack {
    uint64_t sub_id;
    uint64_t batch_id;
    uint32_t n_consumed;
} etap_ack;

typedef struct etap_sub_stats {
    uint64_t delivered_batches;
    uint64_t delivered_pkts;
    uint64_t dropped_pkts;
    uint64_t dropped_bytes;
    uint64_t leased_batches;
    uint32_t queue_depth;
    uint32_t lag_us;
    uint32_t epoch;
    uint32_t schema_id;
} etap_sub_stats;

#pragma pack(pop)

_Static_assert(sizeof(etap_batch_hdr) == 128, "etap_batch_hdr must be 128 bytes");
_Static_assert(sizeof(etap_section) == 24, "etap_section must be 24 bytes");
_Static_assert(sizeof(etap_parse_index_row) == 32, "parse index row must be 32 bytes");
_Static_assert(sizeof(etap_flow_meta_row) == 48, "flow meta row must be 48 bytes");

typedef struct etap_conn  etap_conn;
typedef struct etap_caps  etap_caps;
typedef struct etap_sub   etap_sub;
typedef struct etap_batch etap_batch;
typedef struct etap_schema etap_schema;

/* Subscription request is a variable-length buffer starting with etap_sub_req_hdr. */
typedef struct etap_sub_req {
    const uint8_t *bytes;
    uint32_t       len;
} etap_sub_req;

etap_status etap_open(const char *uri, const etap_open_opt *opt, etap_conn **out);
etap_status etap_close(etap_conn *conn);

etap_status etap_discover(etap_conn *conn, etap_caps **out);
void        etap_caps_free(etap_caps *caps);
const etap_caps_hdr *etap_caps_header(const etap_caps *caps);

etap_status etap_subscribe(etap_conn *conn, const etap_sub_req *req, etap_sub **out);
etap_status etap_resubscribe(etap_sub *sub, const etap_sub_req *req);
etap_status etap_unsubscribe(etap_sub *sub);

etap_status etap_poll(etap_sub *sub, uint32_t timeout_us, etap_batch **out);
etap_status etap_release(etap_batch *batch);

const etap_batch_hdr *etap_batch_header(const etap_batch *batch);
const etap_schema    *etap_batch_schema(const etap_batch *batch);

etap_status etap_col(const etap_batch *batch, uint16_t section_kind, uint32_t col_id,
                     etap_type *type, uint32_t *n,
                     const void **data, const uint8_t **valid,
                     const uint32_t **offsets);

etap_span   etap_packet_bytes(const etap_batch *batch, uint32_t index);

const uint8_t *etap_batch_data(const etap_batch *batch, uint32_t *size);
const uint8_t *etap_caps_data(const etap_caps *caps, uint32_t *size);

const etap_parse_index_row *etap_parse_index(const etap_batch *batch, uint32_t *n);
const etap_flow_meta_row   *etap_flow_meta(const etap_batch *batch, uint32_t *n);

etap_status etap_stats(etap_sub *sub, etap_sub_stats *out);

/* Simulator test hooks (etap://sim). Not used on the model hot path. */
etap_status etap_sim_fill_ring(etap_sub *sub, uint32_t *queued);
etap_status etap_sim_drop(etap_sub *sub, uint64_t n_pkts, uint64_t n_bytes);
etap_status etap_sim_set_limit(etap_sub *sub, uint32_t remaining_pkts);

#ifdef __cplusplus
}
#endif

#endif /* ETAP_H */
