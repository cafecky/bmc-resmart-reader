# BMC RESmart Reader / BMC 瑞迈特读取工具

Version / 版本：v1 + v2 + v3 + three-way analysis（2026-10-28）

## What this is / 这是什么

Read a BMC RESmart SD card (GII / G3 / G3 A20) on macOS with Python standard
library only, and build self-contained HTML reports and CSV tables.
No external Python packages are needed.
只用 Python 标准库，在 Mac 上读取 BMC RESmart（GII / G3 / G3 A20）的 SD 卡，
生成自包含 HTML 报告和 CSV 表。不需要安装第三方 Python 包。

This is a personal data-reading tool, not a medical device, not a diagnosis
tool, and not a replacement for the manufacturer's software. Values may have
errors. Medical or insurance decisions should be based on the device or the
official software, not on this code.
这是个人数据读取工具，不是医疗器械，不是诊断工具，也不能代替厂商官方软件。
数值可能有误差，医疗或保险决定请以设备或官方软件为准。

## Files / 文件

- `generate_bmc_report.py` — v1, complete reader: raw packets, sessions, full
  nights, per-minute curves. v1 完整读取：原始包、会话、完整夜、每分钟曲线。
- `generate_bmc_analysis.py` — v2, full-card analysis: .idx, .evt, .usr header,
  .log, Clarity reference table, and the Clarity comparison conclusions.
  v2 全卡分析：.idx、.evt、.usr 头、.log、Clarity 参考表和对照结论。
- `generate_bmc_report_v3.py` — v3, same decoding as v2, HPS-style presentation:
  blue gradient header, left sidebar (latest night, mode and definitions,
  section navigation), central charts, wide tables below.
  v3：解码与 v2 完全一致，只换呈现，照搬 HPS v3.5 版式。
- `bmc_three_way_analysis.py` — three-way comparison: card raw data +
  OSCAR database + Clarity reference CSV, in one run.
  三方对照：卡上原始数据 + OSCAR 数据库 + Clarity 参考表，一次跑完。

## What is decoded / 已解开

- Raw `.000`–`.029`: one packet per second, 256 bytes, first uint16 is `0xAAAA`.
  IPAP = uint16[2] / 2, EPAP = uint16[3] / 2 (cmH2O), tidal volume field =
  uint16[99] (ml), respiration rate = uint16[104] (/min), 25 Hz pressure /
  flow fields. These field names are reverse-engineered mappings, not the
  manufacturer's official specification.
  原始波形：每秒 1 包，256 字节，首 uint16 为 0xAAAA；IPAP、EPAP、潮气量、
  呼吸频率、25 Hz 压力/流量字段均为逆向工程推测口径，不是厂商官方规格。
- `.idx`: 370 session records, 512 bytes each, data from offset 2048, date /
  time / index; bytes 64–384 are an identical fixed template across records,
  not per-night data; bytes 384–512 are all FF.
  .idx：370 条会话记录，每条 512 字节，数据从 2048 起；64–384 字节在全部记录
  里完全相同，是固定模板，不是每夜数据；384–512 全为 FF。
- `.evt`: 55108 records in 370 groups, 32 bytes each, data from offset 2048.
  Type 1 + 2 + 3 is the AHI numerator candidate; type 11 is NOT counted.
  .evt：55108 条记录，370 组，每条 32 字节，数据从 2048 起；类型 1+2+3 之和
  是 AHI 分子候选，类型 11 不计。
- `.usr`: header only, first 256 bytes (serial + `G3-` marker). Personal
  content after the header is NOT read, NOT decoded, NOT shown.
  .usr：只读前 256 字节头（序列号与 G3- 标记），之后的个人信息不读、不解、不展示。
- `.log`: block-type counts only. It is a software-operation journal, not
  therapy data. .log：只统计块类型，是软件操作日志，不是治疗数据。

## What is verified by OSCAR and Clarity / 经 OSCAR 和 Clarity 验证的部分

- Event type mapping, candidate but strongly supported: type 1 = central,
  type 2 = obstructive, type 3 = hypopnea. In the last 13 nights
  (Clarity 2023-08-13..25), the sum 1+2+3 matches Clarity totals in 12 of 13
  nights; the only exception is one obstructive event in the 2023-08-17 night
  (raw count 7, Clarity and OSCAR both count 6). Until an official对照 output
  arrives, this mapping is still called a candidate, not a confirmed official
  mapping. 类型分工候选：1=中枢、2=阻塞、3=低通气；最后 13 夜里 12 夜与
  Clarity 总数完全一致，仅 2023-08-17 夜阻塞差 1 个（raw 7 个，Clarity 和
  OSCAR 均为 6 个），在拿到官方对照之前仍称候选，不称已确认。
- Denominator: packet count / 3600 (one packet ≈ 1 second) matches OSCAR
  durations in 2023-08-19 (7.88 h) and 2023-08-25 (5.24 h), but Clarity
  durations are shorter in those nights (by about 0.78 h and 0.50 h).
  OSCAR groups sessions by CPAP day (noon to noon) and merges sessions in
  one day, so its daily AHI can differ a lot from Clarity's nightly AHI even
  when event counts are identical. Always state which denominator an AHI uses.
  分母：包数除以 3600 在 08-19、08-25 与 OSCAR 时长一致，Clarity 时长则短
  约 0.78、0.50 小时；OSCAR 按 CPAP 日（中午到中午）合并会话，所以即使事件数
  相同，日常 AHI 也可能跟 Clarity 的单夜 AHI 差很多，引用 AHI 时必须注明分母。
- OSCAR full totals for one G3 A20 card (2020-05-05..2023-08-25, 356 days,
  1892.31 h): 2040 events (obstructive 433, hypopnea 215, central 1392,
  RERA 0), weighted AHI 1.078. Clarity for the same card (353 analysed nights):
  2011 events (obstructive 418, hypopnea 211, central 1382), AHI 1.1.
  Central events are about 68% of all events in both.
  OSCAR 全期一例（2020-05-05..2023-08-25，356 天，1892.31 小时）：2040 个事件，
  加权 AHI 1.078；Clarity 同卡（353 分析夜）：2011 个事件，AHI 1.1；中枢约占 68%。

## What is NOT decoded / 未解开

- Leak: there is no validated leak field on the card. Do not use any raw
  field as leak. Clarity and OSCAR leak values are their own calculations
  from the waveform, not card fields. 漏气：卡上没有已验证的漏气字段，
  不要拿任何原始字段当漏气；Clarity 和 OSCAR 的漏气是各自从波形算的，不是卡上字段。
- Event wall-clock time: `.evt` field A is a counter, not a wall-clock time,
  so events cannot be plotted on a curve time axis. .evt 的 A 字段是计数器，
  不是墙钟时间，不能把事件点画到曲线时间轴上。
- `.idx` header fields beyond date / time / index, and the `.usr` summary area
  after the header, are not claimed as duration / AHI / leak.
  .idx 头里日期时间序号之外的字段、.usr 头之后的汇总区，不当作时长/AHI/漏气。

## How to use / 使用方法

Use a card copy, not the original card, when you can. Do not format the card.
尽量用卡副本，不要直接用原卡；不要点格式化。

```sh
# v3 report, v3 报告
python3 generate_bmc_report_v3.py --path "/path/to/card-copy"

# v2 analysis, v2 分析（需要把你自己的 clarity_reference.csv 放在脚本旁边）
python3 generate_bmc_analysis.py --path "/path/to/card-copy"

# v1 report, v1 报告
python3 generate_bmc_report.py --path "/path/to/card-copy"

# three-way comparison, 三方对照
python3 bmc_three_way_analysis.py \
  --card "/path/to/card-copy" \
  --oscar-db "/path/to/OSCAR20_Data/oscar.db" \
  --clarity-csv clarity_reference.csv \
  --outdir output_three_way
```

The three-way script copies the OSCAR database to a temporary directory
first, then queries the copy, so a running OSCAR instance is not disturbed.
三方对照脚本会先把 OSCAR 数据库拷到临时目录再查，正在运行的 OSCAR 不受影响。

## Do NOT upload health data / 不要上传健康数据

Do NOT commit to GitHub: card files, OSCAR databases, Clarity exports or
reports, generated HTML reports, CSV tables with per-night health data,
or any file containing personal information. Only code and documentation
belong in this repository. A `clarity_reference.csv` is your own export;
it is intentionally NOT included here, and `.gitignore` excludes `*.csv`
and generated outputs.
不要把以下内容提交到 GitHub：卡文件、OSCAR 数据库、Clarity 导出或报告、
生成的 HTML 报告、含每夜健康数据的 CSV、任何含个人信息的文件。本仓库只放
代码与说明。`clarity_reference.csv` 是你自己的导出，本仓库故意不含它，
`.gitignore` 也排除了 `*.csv` 和生成产物。

## License / 许可

MIT License, see `LICENSE`.
