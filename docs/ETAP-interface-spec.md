# ETAP：面向机器的以太网流量感知端口

版本 0.1（草案）  
字节序：除另行说明外，均为小端。  
数据通路禁止使用 JSON、日志或自然语言作为模型输入。字符串只出现在一次性能力目录和人类调试接口中。

---

## 1. 目标

ETAP（Ethernet Traffic Awareness Port）是平台向 AI 计算终端交付流量观察的机器接口。模型通过二进制数据流接收「流量观察批次」，在明确语义的数据视图上进行感知、推理和决策。

接口输出的不是原始包镜像，而是三种可组合的抽象视图：报文视图、解析视图、流视图。模型只订阅需要的字段和字节区间。视图之外的细节默认不提供，以降低带宽、提高信息传递密度。

平台与模型之间的职责划分：

- 平台：过滤、解析、成批、标记数据质量，并按预算交付。
- 模型适配层：根据批次自带的结构描述，将列式缓冲区映射为张量或其他模型输入。
- 模型：消费批次并给出决策。数据面不等待推理完成。

---

## 2. 对象与标识

同一订阅世代（`epoch`）内，下列标识跨三种视图统一，用于回答：这个字段来自哪个报文，这个报文属于哪条流，这段观察发生在什么时间。

| 标识 | 宽度 | 规则 |
| --- | --- | --- |
| `port_id` | u32 | 感知端口实例 |
| `sub_id` | u64 | 订阅 |
| `epoch` | u32 | 标识空间世代。端口重启、标识回绕或破坏性重订阅时加一。模型不得跨 epoch 拼接标识。 |
| `schema_id` | u32 | 本批次列布局的指纹。相同则适配层可复用映射。 |
| `batch_id` | u64 | 批次，在订阅内唯一 |
| `seq` | u64 | 订阅内批次序号，从 0 起严格递增。出现跳号即存在批次级缺口。 |
| `pkt_id` | u64 | 被观察报文的标识，在 `(port_id, epoch)` 内唯一且按观察顺序递增。跳号表示报文级缺口。`0` 保留为无效。 |
| `flow_id` | u64 | 流标识，在 `(port_id, epoch)` 内稳定。`0` 表示未归流。 |
| `msg_id` | u64 | 报文内的协议消息或记录。`0` 表示无消息切分。 |

时间使用 `ts_ns`（u64，纳秒）。时钟域在能力发现和 schema 中声明，同一端口的三种视图共享同一时钟域。常用值：`0` 硬件采集、`1` 软件采集、`2` 单调钟、`3` 实时钟。

---

## 3. 接口结构

接口分为低频的订阅控制和高频的批量数据两部分。两者语义相同，部署位置只改变传输，不改变对象。

- 本机：控制走 Unix 域套接字（或等价 RPC）；数据走共享内存环形缓冲区与可复用 arena，具备条件时零拷贝或少拷贝。
- 远端：同一套消息的紧凑二进制帧，走 TCP、QUIC 或 RDMA。
- URI 示例：`etap://local/port0`，`etap://192.0.2.10:4700/port0`。

### 3.1 动作

| 动作 | 方向 | 含义 |
| --- | --- | --- |
| 发现能力 | 控制，请求/响应 | 查询平台支持的报文范围、协议字段、流特征和数据格式 |
| 建立或调整订阅 | 控制，请求/响应 | 指定观察范围、视图内容、采样方式和资源预算 |
| 接收数据批次 | 数据，单向推送或轮询 | 持续取得符合订阅的「流量观察批次」 |
| 释放或确认批次 | 数据，确认 | 模型已消费完毕，平台可回收缓冲区 |
| 查询状态 / 关闭 | 控制 | 积压、丢弃、时延；取消订阅或关闭连接 |

控制路径不得出现在每报文热路径上。批次确认走数据面（共享内存槽位归还或 `ACK` 帧），以便与吞吐匹配。

---

## 4. 函数接口（C）

见同目录 `etap.h`。语义如下。

```c
etap_status etap_open(const char *uri, const etap_open_opt *opt, etap_conn **out);
etap_status etap_close(etap_conn *conn);

etap_status etap_discover(etap_conn *conn, etap_caps **out);
void        etap_caps_free(etap_caps *caps);

etap_status etap_subscribe(etap_conn *conn, const etap_sub_req *req, etap_sub **out);
etap_status etap_resubscribe(etap_sub *sub, const etap_sub_req *req);
etap_status etap_unsubscribe(etap_sub *sub);

etap_status etap_poll(etap_sub *sub, uint32_t timeout_us, etap_batch **out);
etap_status etap_release(etap_batch *batch);

const etap_schema *etap_batch_schema(const etap_batch *b);
etap_status etap_col(const etap_batch *b, uint32_t col_id,
                     etap_type *type, uint32_t *n,
                     const void **data, const uint8_t **valid, const uint32_t **offsets);
etap_span   etap_packet_bytes(const etap_batch *b, uint32_t index);
etap_status etap_stats(etap_sub *sub, etap_sub_stats *out);
```

`etap_poll`：`timeout_us = 0` 表示非阻塞。无数据返回 `ETAP_EMPTY`，不阻塞采集。  
`etap_release`：必须对每个成功取出的批次调用一次。未释放的批次会占用预算；平台不会因此暂停采集，只会按订阅策略丢弃并报告缺口。  
`etap_col`：返回列的基址、行数、空值位图和变长偏移。适配层据此直接构造张量，不再做语义转换。  
破坏性调整订阅（标识空间或 schema 不兼容）会使 `epoch` 或 `schema_id` 变化；适配层必须重新建立映射。

---

## 5. 能力发现

`etap_discover` 返回一份机器可读目录，供订阅使用。目录可以含字段名，仅用于一次对齐；热路径只使用 `field_id` / `feature_id` / `proto_id`。

### 5.1 `etap_caps` 头

| 偏移 | 字段 | 类型 | 含义 |
| --- | --- | --- | --- |
| 0 | `magic` | u32 | `0x31504154`（「TAP1」） |
| 4 | `version` | u16 | 协议版本，当前 `0x0001` |
| 6 | `hdr_len` | u16 | 头长度 |
| 8 | `flags` | u32 | 见下表 |
| 12 | `port_id` | u32 | |
| 16 | `clock` | u8 | 时钟域 |
| 17 | `endian` | u8 | `0` 小端 |
| 18 | `reserved0` | u16 | `0` |
| 20 | `max_batch_records` | u32 | 单批次最大记录数 |
| 24 | `max_batch_bytes` | u32 | 单批次最大字节 |
| 28 | `min_wait_us` | u32 | 允许的最小成批等待 |
| 32 | `max_wait_us` | u32 | 允许的最大成批等待 |
| 36 | `max_slice` | u32 | 单报文最多可订阅的原始字节 |
| 40 | `view_mask` | u32 | bit0 报文，bit1 解析，bit2 流 |
| 44 | `n_protos` | u16 | |
| 46 | `n_fields` | u16 | |
| 48 | `n_features` | u16 | 流特征数 |
| 50 | `reserved1` | u16 | |
| 52 | `protos_off` | u32 | |
| 56 | `fields_off` | u32 | |
| 60 | `features_off` | u32 | |
| 64 | `strtab_off` | u32 | 字符串表 |
| 68 | `strtab_len` | u32 | |
| 72 | `time_res_ns` | u32 | 时间分辨率 |
| 76 | `snaplen_max` | u32 | 平台最大截断长度 |

`flags` 能力位：

| 位 | 名称 | 含义 |
| --- | --- | --- |
| 0 | `SHM` | 支持本机共享内存 |
| 1 | `REMOTE` | 支持远端批量传输 |
| 2 | `ZEROCOPY` | 支持缓冲区出借 |
| 3 | `SAMPLE` | 支持采样 |
| 4 | `AGGREGATE` | 支持聚合后交付 |
| 5 | `BPF` | 过滤可用 BPF 字节码 |
| 6 | `STRUCT_FILTER` | 过滤可用结构化谓词 |
| 7 | `RDMA` | 支持 RDMA |

### 5.2 目录项

协议项 `etap_proto_desc`（16 字节）：`proto_id u32`，`parent_id u32`（无则 0），`name_off u32`，`name_len u16`，`flags u16`。

字段项 `etap_field_desc`（20 字节）：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `field_id` | u32 | 稳定编号 |
| `proto_id` | u32 | 所属协议 |
| `type` | u16 | 见第 8 节类型码 |
| `flags` | u16 | bit0 可选，bit1 变长，bit2 键字段 |
| `name_off` | u32 | |
| `name_len` | u16 | |
| `reserved` | u16 | |
| `reserved2` | u32 | 补齐到 32 字节 |

流特征项 `etap_feature_desc` 布局与字段项相同，使用 `feature_id`。特征是流在一段时间窗口内的累计或统计量，不是单报文协议字段。

---

## 6. 订阅

订阅描述模型想观察什么，以及在资源不足时如何降级。调整订阅是控制面操作，频率应远低于批次到达频率。

### 6.1 `etap_sub_req`

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `req_len` | u32 | 本请求总长度 |
| `flags` | u32 | bit0 允许破坏性变更（可换 epoch） |
| `view_mask` | u32 | 需要的视图组合 |
| `max_records` | u32 | 成批：最多记录数 |
| `max_bytes` | u32 | 成批：最多字节 |
| `max_wait_us` | u32 | 成批：最多等待。`0` 表示不等待（低时延，批次可能很小） |
| `budget_rps` | u32 | 目标最大记录/秒，`0` 不限制 |
| `budget_bps` | u64 | 目标最大字节/秒，`0` 不限制 |
| `overflow` | u8 | `0` 采样，`1` 聚合，`2` 丢弃。无论哪种都必须报告缺口 |
| `sample_mode` | u8 | `0` 无，`1` 按 `flow_id` 哈希取模，`2` 每流前 K 包，`3` 每 N 包取 1，`4` 令牌桶 |
| `sample_n` | u32 | 采样参数 N 或 K |
| `sample_k` | u32 | 令牌桶突发等辅参数 |
| `filter_off` | u32 | 过滤表达式 |
| `filter_len` | u32 | |
| `packet_off` | u32 | 报文视图描述 |
| `parse_off` | u32 | 解析视图描述 |
| `flow_off` | u32 | 流视图描述 |

### 6.2 报文视图描述 `etap_packet_sel`

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `meta_mask` | u32 | 需要的元数据列，见下 |
| `bytes_mode` | u8 | `0` 不要原始字节，`1` 头（链路到传输层头），`2` 指定区间，`3` 从 0 起 `max_bytes`，`4` 不超过平台 snaplen 的全部已捕获字节 |
| `n_ranges` | u8 | `bytes_mode=2` 时的区间数 |
| `reserved` | u16 | |
| `max_bytes` | u16 | 单包最多复制的字节 |
| `range[]` | `{u16 off, u16 len}` | 相对帧起始的闭开区间 |

`meta_mask` 位：0 `pkt_id`，1 `flow_id`，2 `ts_ns`，3 `wire_len`，4 `cap_len`，5 `dir`，6 `ifindex`，7 `flags`，8 `l3_off`，9 `l4_off`，10 `payload_off`。至少应订阅 `pkt_id` 与 `ts_ns`，否则无法与其他视图或时间对齐。

### 6.3 解析视图描述 `etap_parse_sel`

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `flags` | u16 | bit0 要消息边界，bit1 要字段相对原始报文的偏移和长度 |
| `n_protos` | u16 | `0` 表示不限协议，仅输出已列字段 |
| `n_fields` | u16 | |
| `reserved` | u16 | |
| `proto_ids[]` | u32 | |
| `field_ids[]` | u32 | 只输出这些字段 |

未列入的字段不得出现在批次中。不要为每个模型做完整协议解码再丢弃。

### 6.4 流视图描述 `etap_flow_sel`

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `event_mask` | u16 | bit0 New，1 Update，2 Expire，3 Reset，4 Anomaly |
| `flags` | u16 | bit0 附带本批次内该流的 `pkt_id` 索引 |
| `n_features` | u16 | |
| `reserved` | u16 | |
| `feature_ids[]` | u32 | |

### 6.5 过滤

优先使用结构化谓词树（二进制），避免把人类规则文本送进数据面。节点为定长头加载荷：`op u8`（0 AND，1 OR，2 NOT，3 PRED），`pred u8`，`n_children u8`，`len u8`，随后是子节点或立即数。

常用谓词：`ifindex`、`dir`、`ethertype`、`vlan`、`ip_ver`、`ip_proto`、`src_cidr`、`dst_cidr`、`sport`、`dport`、`l7_proto`、`flow_event`。可选附加 BPF 字节码，由 `caps.flags.BPF` 声明。

### 6.6 订阅响应 `etap_sub_ack`

`sub_id u64`，`epoch u32`，`schema_id u32`，`granted_flags u32`，`effective_max_records u32`，`effective_max_bytes u32`，`effective_max_wait_us u32`，以及生效后的 schema（或 schema 引用）。若平台削减了预算或字段，必须在 `granted_flags` 中置 `REDUCED`，并给出实际生效的选择，不得 silently 少送又不声明。

---

## 7. 流量观察批次

核心对象是 `etap_batch`。一个批次可组合三种视图，未订阅的节段不出现。报文字节放在连续缓冲区中；解析结果和流特征使用有类型的列式数组；变长内容用 `(offset, length)` 引用堆区。批次自带或引用机器可读 schema，适配层据此映射输入。

### 7.1 批次头（128 字节）

| 偏移 | 字段 | 类型 | 含义 |
| --- | --- | --- | --- |
| 0 | `magic` | u32 | `0x31504154` |
| 4 | `version` | u16 | `0x0001` |
| 6 | `hdr_len` | u16 | `128` |
| 8 | `flags` | u32 | 批次级标记，见第 9 节 |
| 12 | `n_sections` | u16 | |
| 14 | `clock` | u8 | |
| 15 | `reserved0` | u8 | |
| 16 | `batch_id` | u64 | |
| 24 | `sub_id` | u64 | |
| 32 | `epoch` | u32 | |
| 36 | `schema_id` | u32 | |
| 40 | `seq` | u64 | |
| 48 | `time_first_ns` | u64 | 本批最早观察时间 |
| 56 | `time_last_ns` | u64 | 本批最晚观察时间 |
| 64 | `n_packets` | u32 | 报文视图行数 |
| 68 | `n_parse_rows` | u32 | 解析视图行数 |
| 72 | `n_flows` | u32 | 流视图行数 |
| 76 | `reserved1` | u32 | |
| 80 | `gap_dropped_pkts` | u64 | 自上一成功交付批次以来丢掉的报文数 |
| 88 | `gap_dropped_bytes` | u64 | 对应的线长合计 |
| 96 | `gap_first_pkt_id` | u64 | 缺口区间的下界（含）。无缺口为 0 |
| 104 | `gap_last_pkt_id` | u64 | 缺口区间的上界（含）。无缺口为 0 |
| 112 | `producer_lag_us` | u32 | 采集到入批的滞后估计 |
| 116 | `crc32c` | u32 | 覆盖头和节目录；`0` 表示未计算 |
| 120 | `sections_off` | u32 | 相对批次起始 |
| 124 | `total_size` | u32 | 含头的总字节 |

节目录在 `sections_off`，每项 24 字节：`kind u16`，`flags u16`，`count u32`，`off u64`，`size u64`。`off` 相对批次起始，8 字节对齐。

### 7.2 节类型

| `kind` | 名称 | 内容 |
| --- | --- | --- |
| 1 | `PACKET_META` | 报文元数据列组 |
| 2 | `PACKET_BYTES` | 连续原始字节堆 |
| 3 | `PARSE_INDEX` | 解析行到报文/消息的索引 |
| 4 | `PARSE_COLS` | 订阅字段的列式数据 |
| 5 | `FLOW_META` | 流事件与生命周期 |
| 6 | `FLOW_FEAT` | 订阅的流特征列 |
| 7 | `FLOW_PKTS` | 流到本批次 `pkt_id` 的索引 |
| 8 | `SCHEMA` | 仅当 `schema_id` 首次出现或变更时内嵌 |
| 9 | `HEAP` | 变长字节/字段的共享堆 |
| 10 | `GAP` | 可选的分段缺口明细 |

### 7.3 列组编码

`PACKET_META`、`PARSE_COLS`、`FLOW_FEAT` 使用相同的列组前缀：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `n_cols` | u16 | |
| `n_rows` | u32 | 与节 `count` 一致 |
| `flags` | u16 | bit0 含空值位图 |
| 随后 `n_cols` 个列描述 | 16 字节 | 见下 |
| 随后列数据，每列 8 字节对齐 |  | |

列描述：`col_id u32`（报文元数据为固定编号 1–11，解析为 `field_id`，流为 `feature_id`），`type u16`，`flags u16`（bit0 有 validity，bit1 变长），`data_off u32`，`data_len u32`（均相对本列组起始）。

定长列：`n_rows * width` 个紧密元素。  
变长列：`u32 offsets[n_rows+1]`，内容在 `HEAP` 或本列 `data` 区，区间为 `[offsets[i], offsets[i+1])`。  
空值位图：行 `i` 的第 `i` 位为 0 表示该字段缺失。位图按 bit little-endian 打包，长度 `ceil(n_rows/8)`，再补齐到 8 字节。缺失不得用 0、空串或 `N/A` 填充后让模型当成有效值。

### 7.4 报文视图

固定 `col_id`：

| col_id | 名称 | 类型 | 含义 |
| --- | --- | --- | --- |
| 1 | `pkt_id` | u64 | |
| 2 | `flow_id` | u64 | 可 0 |
| 3 | `ts_ns` | u64 | 该包观察时间 |
| 4 | `wire_len` | u32 | 线上长度 |
| 5 | `cap_len` | u32 | 捕获/切片后长度 |
| 6 | `dir` | u8 | `0` 入，`1` 出，`2` 未知 |
| 7 | `ifindex` | u32 | |
| 8 | `flags` | u16 | 记录级标记，见第 9 节 |
| 9 | `l3_off` | u16 | 相对本包字节缓冲 |
| 10 | `l4_off` | u16 | |
| 11 | `bytes_off` / `bytes_len` | u32, u32 | 在 `PACKET_BYTES` 中的位置与长度 |

`PACKET_BYTES` 是连续缓冲，报文按 8 字节对齐依次放置。只包含订阅的字节区间，不是完整镜像。`cap_len < wire_len` 或 `flags.TRUNCATED` 表示截断。`bytes_mode=0` 时无此节，模型仍可仅用长度与时间工作。

### 7.5 解析视图

`PARSE_INDEX` 每行 32 字节：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `pkt_id` | u64 | 来源报文 |
| `msg_id` | u64 | 消息标识 |
| `proto_id` | u32 | |
| `msg_off` | u16 | 消息相对该包字节缓冲的起始 |
| `msg_len` | u16 | 消息长度 |
| `flags` | u16 | 含 `PARSE_INCOMPLETE`、`PARSE_ERROR` |
| `reserved` | u16 | |

`PARSE_COLS` 与 `PARSE_INDEX` 行对齐（同一 `n_rows`、同一顺序）。若订阅了字段偏移，则为每个变长或需要定位的字段额外提供并行列：`field_off u16`、`field_len u16`（相对该包字节缓冲；字段缺失则 validity=0）。这样模型既使用类型化字段值，也能回到原始字节。

一行对应「某一报文中的一条协议消息」。一个报文可有多行（例如一个 TLS record + 内层 HTTP）。无解析结果的报文不出现在解析视图中，这不等于「该报文没有协议」，除非同时能从报文视图看到该 `pkt_id` 且解析失败被显式标记。

### 7.6 流视图

`FLOW_META` 每行 48 字节：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `flow_id` | u64 | |
| `event` | u8 | 1 New，2 Update，3 Expire，4 Reset，5 Anomaly |
| `state` | u8 | 1 尝试，2 已建立，3 关闭中，4 已结束，5 异常 |
| `flags` | u16 | |
| `ifindex` | u32 | |
| `start_ns` | u64 | 流开始 |
| `last_ns` | u64 | 本事件对应的最后观察时间 |
| `pkt_id_first` | u64 | 该流在 epoch 内首个已观察 `pkt_id`（可能早于本批次；若未知且有缺口，置 0 并置 `GAP`） |
| `pkt_id_last` | u64 | 截至本事件的最后 `pkt_id` |

`FLOW_FEAT` 与 `FLOW_META` 行对齐。推荐但并非强制的特征 ID 空间（平台目录为准）：

| feature_id | 名称 | 类型 |
| --- | --- | --- |
| 1 | `pkts_fwd` | u64 |
| 2 | `pkts_rev` | u64 |
| 3 | `bytes_fwd` | u64 |
| 4 | `bytes_rev` | u64 |
| 5 | `duration_ns` | u64 |
| 6 | `iat_mean_ns` | u64 |
| 7 | `iat_max_ns` | u64 |
| 8 | `retrans` | u32 |
| 9 | `ooo` | u32 |
| 10 | `rtt_ns` | u64 |
| 11 | `syn` | u32 |
| 12 | `rst` | u32 |
| 13 | `psh` | u32 |
| 14 | `win_min` | u32 |

`FLOW_PKTS`：对每个流给出本批次中属于它的报文下标或 `pkt_id` 列表，编码为变长列（`offsets` + `u64 pkt_id[]`）。用于把时序模型的流状态和报文序列对齐。

---

## 8. 类型与 schema

类型码 `etap_type`：

| 值 | 名称 | 宽度 |
| --- | --- | --- |
| 1 | `u8` | 1 |
| 2 | `u16` | 2 |
| 3 | `u32` | 4 |
| 4 | `u64` | 8 |
| 5 | `i8` | 1 |
| 6 | `i16` | 2 |
| 7 | `i32` | 4 |
| 8 | `i64` | 8 |
| 9 | `bool` | 1 |
| 10 | `f32` | 4 |
| 11 | `f64` | 8 |
| 12 | `mac` | 6 |
| 13 | `ipv4` | 4 |
| 14 | `ipv6` | 16 |
| 15 | `enum` | 4（值为稳定枚举 ID，不是字符串） |
| 16 | `bytes` | 变长 |
| 17 | `ts_ns` | 8 |
| 18 | `dur_ns` | 8 |

`SCHEMA` 节在 `schema_id` 变化时随批次出现一次，之后只传 `schema_id`。内容包括：列清单（`col_id/field_id/feature_id`、类型、flags、所属节）、时钟域、`epoch`、对齐规则。适配层缓存 `(schema_id -> 张量布局)`。schema 中可以带字段名供调试，模型热路径不得依赖名称。

枚举和协议名通过发现目录的 ID 使用。不得在每个批次中重复传送「TCP」「HTTP」这类文本。

---

## 9. 数据质量标记

「没有观察到」不得被写成「没有发生」。标记分批次级和记录级。

批次 `flags`：

| 位 | 名称 | 含义 |
| --- | --- | --- |
| 0 | `HAS_GAP` | 与上一批次之间存在未交付观察，详见 `gap_*` |
| 1 | `SAMPLED` | 本批数据经过采样 |
| 2 | `AGGREGATED` | 含聚合结果，不是逐包完整观察 |
| 3 | `TRUNCATED` | 至少一条记录发生字节截断 |
| 4 | `SCHEMA_EMBEDDED` | 含 `SCHEMA` 节 |
| 5 | `CLOCK_DISCONT` | 时钟回跳或不连续 |
| 6 | `OVERFLOW` | 因消费者慢或预算触发了溢出策略 |
| 7 | `END_OF_EPOCH` | 随后 `epoch` 将变化，适配层应重置状态 |

记录 `flags`（报文 / 解析 / 流）：

| 位 | 名称 | 含义 |
| --- | --- | --- |
| 0 | `SAMPLED` | 该记录是采样结果 |
| 1 | `TRUNCATED` | 字节或字段被截断 |
| 2 | `GAP_BEFORE` | 该记录之前存在序列缺口 |
| 3 | `MISSING_DEP` | 依赖的下层字段缺失 |
| 4 | `PARSE_INCOMPLETE` | 解析未完成（长度不够、分片未齐等） |
| 5 | `PARSE_ERROR` | 解析失败 |
| 6 | `AGGREGATED` | 该流/记录为聚合 |
| 7 | `CSUM_ERR` | 校验和错误（若平台检查） |

字段级缺失只用 validity 位图，不占用上述记录标志的语义。  
`gap_dropped_pkts = 0` 且未置 `HAS_GAP` 才表示序列完整。模型若把「本批没有某 `pkt_id`」直接当作「该包未出现在链路上」，属于误用。

---

## 10. 传输

### 10.1 远端帧

每帧：`len u32`（随后字节数，不含 `len` 自身），`type u16`，`flags u16`，`corr_id u64`（请求响应配对；数据帧为 0），再加载荷。`len` 最大由连接协商，默认 16 MiB。

| type | 名称 | 载荷 |
| --- | --- | --- |
| 1 | `DISCOVER_REQ` | 可空 |
| 2 | `DISCOVER_RSP` | `etap_caps` |
| 3 | `SUBSCRIBE_REQ` | `etap_sub_req` |
| 4 | `SUBSCRIBE_RSP` | `etap_sub_ack` + 可选 schema |
| 5 | `RESUBSCRIBE_REQ` | `sub_id` + `etap_sub_req` |
| 6 | `UNSUBSCRIBE_REQ` | `sub_id` |
| 7 | `OK` | 可选 `sub_id` |
| 8 | `ERROR` | `code u32`，`detail_len u16`，二进制或 UTF-8 调试信息（非模型输入） |
| 9 | `BATCH` | 完整 `etap_batch` |
| 10 | `ACK` | `sub_id u64`，`batch_id u64`，`n_consumed u32` |
| 11 | `STATS_REQ` / `STATS_RSP` | 积压、丢弃、滞后 |
| 12 | `HEARTBEAT` | `ts_ns` |

`BATCH` 发出后即视为占用预算。收到 `ACK` 后平台回收。超时未确认按溢出策略处理，并在后续批次置 `HAS_GAP` / `OVERFLOW`。数据面不等待模型推理，只等待缓冲区归还；归还过慢等同于消费过慢。

### 10.2 本机共享内存

控制套接字完成发现与订阅后，响应中给出 shm 名称、大小和槽位数。布局：

```
Header（4096 字节对齐）
  magic, version, n_slots, slot_size_max
  produce_idx, consume_idx   // 原子
  drop_count, drop_bytes     // 原子，供适配层读缺口
  epoch, sub_id, schema_id
Slot[i]
  state      // EMPTY / READY / LEASED
  batch_id, seq, size, arena_off
  lease_gen
Arena
  可复用的连续批次缓冲
```

`etap_poll` 将槽位从 `READY` 转为 `LEASED` 并返回零拷贝指针。`etap_release` 将其置回 `EMPTY`。生产者发现无空槽时不得阻塞采集：按订阅执行采样、聚合或丢弃，并增加 `drop_*`，下一成功批次必须带缺口标记。

本机与远端的批次字节布局相同，便于同一适配层处理。

---

## 11. 消费速度与反压

高性能依赖四条约束，均由本接口落实：

1. **按需提供。** 订阅可以只取包长与时间，也可以取指定字段或字节区间；平台不为未订阅内容付解析和拷贝成本。
2. **批量交付。** `max_records`、`max_bytes`、`max_wait_us` 由模型选择吞吐和等待的折中。
3. **传输适配位置。** 本机共享内存，远端紧凑批量帧，语义一致。
4. **消费速度受控。** AI 变慢时，数据面继续前进：按 `overflow` 采样、聚合或丢弃，并报告缺口。不得用采集阻塞来迁就推理时延。

建议适配层把 `gap_dropped_pkts`、`HAS_GAP`、`SAMPLED`、`producer_lag_us` 和 `etap_stats` 中的积压一并作为模型侧信道输入，供异常检测判断「可见性下降」与「流量本身变化」。

---

## 12. 适配层映射规则

- 每个定长列 → 形状 `[n_rows]` 或 `[n_rows, width]` 的张量，dtype 与 `etap_type` 对应。
- 变长字节（原始报文、字段载荷）→ `values: uint8[total]` 加 `offsets: int32[n_rows+1]`，或按本批最大长度填充为 `[n_rows, max_len]` 并另给 `lengths`。
- validity 位图 → 同形状的 mask；被 mask 关闭的位置不得当数值 0 训练或推理，除非模型显式定义了缺失编码。
- 用 `pkt_id` / `flow_id` / `msg_id` / `ts_ns` 做 join，不要用批次内下标跨批次保存状态。
- `epoch` 或 `schema_id` 变化时清空循环状态。
- 不得把批次再序列化成 JSON 或提示词后送给本接口所面向的计算终端。若另有解释性出口，那是旁路，不是本端口的数据语义。

---

## 13. 状态码

| 码 | 名称 | 含义 |
| --- | --- | --- |
| 0 | `ETAP_OK` | |
| 1 | `ETAP_EMPTY` | 当前无批次 |
| 2 | `ETAP_TIMEOUT` | 等待超时且无批次 |
| 3 | `ETAP_UNSUPPORTED` | 不支持的视图、字段或传输 |
| 4 | `ETAP_INVALID` | 请求不合法 |
| 5 | `ETAP_REDUCED` | 订阅被削减后生效（成功，但需读 ack） |
| 6 | `ETAP_STALE_EPOCH` | 使用了过期 epoch |
| 7 | `ETAP_NOMEM` | 控制面资源不足（数据面超限走缺口，不走此码阻塞） |
| 8 | `ETAP_IO` | 连接或映射失败 |
| 9 | `ETAP_CLOSED` | 已关闭 |
| 10 | `ETAP_SCHEMA` | schema 无法解析 |

---

## 14. 最小交互例子

1. `open("etap://local/eth0")` → `discover` → 得到 `field_id` 目录。  
2. 订阅：报文只要 `pkt_id, flow_id, ts_ns, wire_len, flags` 和前 128 字节；解析只要 `tcp.sport, tcp.dport, tls.sni`；流只要 New/Expire 与 `pkts_fwd, pkts_rev, bytes_fwd, bytes_rev`。`max_records=256`，`max_wait_us=2000`，`overflow=sample`。  
3. 循环 `poll` → 适配层按 schema 映射张量 → 推理 → `release`。  
4. 若某批 `HAS_GAP=1` 且 `gap_dropped_pkts=193`，模型应将这 193 个报文视为「未观察到」，而不是「这 2 ms 内链路只有本批报文」。

本规范定义的是接口语义、函数、通信协议和字段。采集器、协议解析器和模型实现不在本文件范围内。
