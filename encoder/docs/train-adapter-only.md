# 只训适配器就能先跑通

本文说明仓库里这套最小 Qwen3.5 ETAP 适配器如何工作，以及怎样在不下载 2B 权重、不改词表的前提下，先把训练通路跑通。

目标模型是 [Qwen/Qwen3.5-2B-Base](https://huggingface.co/Qwen/Qwen3.5-2B-Base)（隐藏维度 2048，词表 248320，24 层）。默认测试和默认训练都不用这组权重，而是用同尺寸的 `FakeQwen` 代替。

## 1. 为什么先冻结语言模型

适配器要解决的是「三种流量视图怎么进模型」，不是「怎么重写一个语言模型」。把 2B 参数全部打开，既贵又难判断是适配器坏了还是模型在记答案。

因此第一步只训练适配器：

- 语言模型的词嵌入、主干和 `lm_head` 全部冻结（`requires_grad=False`）。
- 只有 `EtapAdapter` 里的参数可训练。
- 监督信号来自模拟器自己的列（协议、目的端口类别、流事件），不是人工写的流量散文。
- 损失只计算短答案 token；前缀、适配器位置、问题位置的 label 都是 `-100`。

等这条通路稳定后，再按需解冻 Qwen 做继续预训练或微调。不要一上来就训语言模型。

## 2. 为什么用 `inputs_embeds`，而不是新的特殊 token

流量不是文本。如果把报文变成 JSON、日志、十六进制或自然语言描述再送进分词器，等于让模型读散文，而且会丢掉列式密度和 validity 信息。

本实现也不扩词表、不训练 token embedding、不借用 Qwen 的视觉编码器或图像 token。做法是：

1. 用冻结的文本嵌入得到短前缀和短问题（例如 `ETAP traffic.` 和 `protocol?`）。
2. 适配器把 flow → packet → parse 编成一段 2048 维向量，直接接到前缀后面。
3. 再接上问题的文本嵌入，以及答案的文本嵌入。
4. 整段序列作为 `inputs_embeds` 送进语言模型。适配器 token 没有对应的 `input_ids`，因此不必改分词器。

拼接顺序：

```
[前缀文本嵌入] [适配器：流 → 报文 → 解析] [问题文本嵌入] [答案文本嵌入]
label:  -100 …  -100 …                     -100 …          答案 id（其余 -100）
```

因果语言模型按常规右移一位计算交叉熵：最后一个问题 token 负责预测第一个答案 token。

## 3. 数据通路（列式张量，不是文本）

1. 通过 C API 打开 `etap://sim`，做 `discover`，再按 `tests/test_etap.c` 里 `build_full_req` 的布局订阅三种视图。
2. `etap_poll` 拿到批次后，立即把列拷贝成 NumPy / 张量（带 validity 位图），然后 `etap_release`。缺失列记为零并置 validity=0，不崩溃。
3. 三种视图分别编码，每种视图一行一个 token：
   - **报文**：长度类列做 `log1p`；方向、ifindex、flags、L3/L4 偏移、相对时间戳作数值特征；报文字节按 16 字节 patch 做小嵌入，再池化成该报文的一个 token。
   - **解析**：`proto_id` 做 embedding；IPv4 当作 4 个字节（不是点分十进制字符串）；端口按 `port / 65535` 缩放；TLS SNI、HTTP Host 按字节 patch 编码，不当成文本分词。一行解析记录一个 token。
   - **流**：event / state 做 embedding；正向/反向包数与字节数、持续时间做 `log1p`。一条流一个 token。
4. 按 flow → packet → parse 拼接，加上视图类型 embedding，经小型 MLP + RMSNorm 投影到 `hidden_size=2048`。

报文字节在整条通路上都是 `uint8` / `int64` 张量，不会被转成十六进制字符串或 JSON。

## 4. 精确冻结清单

调用 `EtapQwenModel.freeze_lm()` 之后：

| 模块 | 是否训练 |
| --- | --- |
| `lm.embed_tokens`（文本词嵌入） | 冻结 |
| `lm` 主干（注意力、MLP、RMSNorm） | 冻结 |
| `lm.lm_head` | 冻结 |
| 分词器 / 词表大小 | 不改、不训练 |
| Qwen 视觉编码器 / 图像 token | 不接入、不使用 |
| `adapter.flow` / `adapter.packet` / `adapter.parse` | 训练 |
| `adapter.view_type` | 训练 |
| `adapter.proj`、`adapter.out_norm` | 训练 |

优化器只接收 `model.adapter.parameters()`。测例会检查：一步更新后，语言模型权重与更新前逐 bit 相同，且至少有一个适配器参数发生变化。

接到真实 Qwen3.5-2B-Base 时，冻结范围相同：所有语言侧参数（embeddings、24 层主干、`lm_head`）保持冻结，只训适配器。

## 5. 模拟器标签怎么来

`etap://sim` 生成确定性的 HTTP / TLS 流量。标签直接从已订阅的列得出，见 `etap_encoder/labels.py`：

| 任务 | 问题 | 答案来源 |
| --- | --- | --- |
| `protocol` | `protocol?` | 首行解析记录的 `proto_id`（编号映射为 `http` / `tls` 等，不用目录字符串） |
| `dport` | `dport?` | 第一个有效的 `tcp.dport`：80 → `http`，443 → `https`，其余 → `other` |
| `event` | `event?` | 首条流的 `event`：`new` / `update` / `expire` / `reset` / `anomaly` |

没有人工撰写的报文说明。一个训练步消费一批模拟流量，按 `protocol` → `dport` → `event` 轮换任务。

## 6. 用 FakeQwen 把通路跑通

`FakeQwen` 与 Qwen3.5-2B-Base 一样使用 `hidden_size=2048`，但词表很小（只覆盖上述前缀、问题和答案），并且只有一层因果注意力。它的作用是让 `inputs_embeds`、冻结检查和反向传播能在 CPU 上验证，不必下载 2B 权重。

在仓库根目录：

```bash
# 1. 编译测试二进制和 Python 用的共享库
./build.sh && ./build/test_etap

# 2. CPU 版 PyTorch（只需做一次）
python3 -m venv encoder/.venv
. encoder/.venv/bin/activate
pip install -r encoder/requirements.txt --index-url https://download.pytorch.org/whl/cpu

# 3. 适配器测例（走 etap://sim + FakeQwen）
PYTHONPATH=encoder python -m unittest discover -s encoder/tests -v

# 4. 默认训练：若干步模拟批次，只更新适配器
PYTHONPATH=encoder python encoder/scripts/train_adapter.py --steps 5 --device cpu
```

`train_adapter.py` 默认 `--model fake`。测例不会下载任何 Hugging Face 模型。

## 7. 之后如何接上真正的 Qwen3.5-2B-Base

适配器输出已经是 2048 维，和官方隐藏维度对齐。接真模型时：

1. 自行安装 `transformers`，并准备好 `Qwen/Qwen3.5-2B-Base` 的本地或缓存权重。本仓库的测试不会执行下载。
2. 运行：

```bash
PYTHONPATH=encoder python encoder/scripts/train_adapter.py \
  --model Qwen/Qwen3.5-2B-Base \
  --steps 5 --device cpu
```

3. `load_language_model()` 会用该模型的输入嵌入和因果主干预计算 logits，拼接方式与 FakeQwen 相同：`inputs_embeds`，不改词表。
4. 仍然先调用 `freeze_lm()`，只把适配器参数交给优化器。
5. 前缀、问题和答案需要改成该模型分词器能编码的短字符串；任务仍建议使用模拟器列标签。
6. 确认 `config.hidden_size == 2048`。若使用其他尺寸的 Qwen，需要按实际隐藏维度构造 `EtapAdapter(hidden_size=...)`。

显存或内存不够时，保持 CPU / 小批次 / 短序列，或自行改用量化加载；这不属于最小实现的范围。

## 8. 不要做的事

- 不要在数据通路上把流量变成 JSON、日志、十六进制转储或自然语言报文描述。
- 不要先训练语言模型再「顺便」加适配器；先冻结 LLM，只训适配器。
- 不要为流量扩词表，也不要训练 token embedding。
- 不要把 Qwen 自带的视觉编码器或图像 token 复用到流量上。流量走 ETAP 三种列式视图和本适配器。
- 不要编造 `etap.h` / 参考实现 / 接口文档里不存在的列或字段 ID。
- 不要把 `encoder/.venv` 或 2B 权重提交进 git。

## 9. 命令速查

```bash
./build.sh && ./build/test_etap
PYTHONPATH=encoder python -m unittest discover -s encoder/tests -v
PYTHONPATH=encoder python encoder/scripts/train_adapter.py --steps 5
# 可选，需自行准备权重：
# PYTHONPATH=encoder python encoder/scripts/train_adapter.py --model Qwen/Qwen3.5-2B-Base
```
