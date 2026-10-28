#!/usr/bin/env python3
# BMC RESmart full-card analysis page, v3 (HPS-style presentation; decoding unchanged from v2).
# Reads ONLY the card (or a card copy). Never writes to the card.
# Decodes, with evidence, what is validated; marks what is NOT decoded.
# AHI/leak from CPAP Clarity are NOT directly output here; see section 7 for the partially verified 1+2+3 / packet-count formula: they are shown only
# when a Clarity reference CSV is supplied, and are labelled as such.
# .usr personal content is never read beyond the 256-byte header
# (serial + "G3-" marker). .log is counted by block type only.
import os, sys, glob, struct, json, csv, argparse, html
from collections import Counter, defaultdict
from datetime import datetime, timedelta

def find_card(explicit):
    if explicit:
        return explicit
    for vol in sorted(glob.glob("/Volumes/*")):
        if glob.glob(os.path.join(vol, "*.[0-9][0-9][0-9]")):
            return vol
    return None

def read_idx(card):
    files = glob.glob(os.path.join(card, "*.idx"))
    if not files:
        return [], None
    data = open(files[0], "rb").read()
    recs = []
    for i in range(370):
        off = 2048 + i * 512
        if off + 512 > len(data):
            break
        r = data[off:off+512]
        if r[0:2] != b"\xaa\xaa":
            break
        idx = struct.unpack("<H", r[2:4])[0]
        y = 2000 + r[4]; m = r[5]; d = r[6]
        hh = r[8]; mm = r[9]; ss = r[10]
        try:
            dt = datetime(y, m, d, hh, mm, ss)
            datestr = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = None; datestr = "%04d-%02d-%02d %02d:%02d:%02d" % (y, m, d, hh, mm, ss)
        recs.append({"n": idx, "date": datestr, "dt": dt.isoformat() if dt else None,
                     "header_hex": r[:64].hex(), "payload_identical": None})
    # payload check: bytes 64-384 identical across records?
    payloads = set()
    for i in range(min(370, len(recs))):
        off = 2048 + i * 512
        payloads.add(data[off+64:off+384])
    identical = (len(payloads) == 1)
    for r in recs:
        r["payload_identical"] = identical
    return recs, files[0]

def read_evt(card):
    files = glob.glob(os.path.join(card, "*.evt"))
    if not files:
        return {}, 0, None
    data = open(files[0], "rb").read()
    groups = defaultdict(list)
    total = 0
    for off in range(2048, len(data) - 31, 32):
        r = data[off:off+32]
        if r[0:2] != b"\xaa\xaa":
            continue
        total += 1
        g = struct.unpack("<H", r[2:4])[0]
        t = struct.unpack("<H", r[4:6])[0]
        a = struct.unpack("<H", r[8:10])[0]
        b = struct.unpack("<H", r[12:14])[0]
        c = struct.unpack("<H", r[18:20])[0]
        groups[g].append((t, a, b, c))
    summary = {}
    for g, lst in groups.items():
        cnt = Counter(t for t, a, b, c in lst)
        summary[g] = {"n": len(lst), "types": dict(sorted(cnt.items())),
                      "a_max": max(a for t, a, b, c in lst),
                      "small_types": sum(cnt[t] for t in (1, 2, 3, 11) if t in cnt)}
    return summary, total, files[0]

def read_raw_sessions(card):
    files = sorted(glob.glob(os.path.join(card, "*.[0-9][0-9][0-9]")))
    packets = []
    for fn in files:
        data = open(fn, "rb").read()
        for i in range(len(data) // 256):
            pkt = data[i*256:(i+1)*256]
            if struct.unpack("<H", pkt[0:2])[0] != 0xAAAA:
                continue
            y, mo, d, h, mi, s = struct.unpack("<HBBBBB", pkt[248:255])
            try:
                dt = datetime(y, mo, d, h, mi, s)
            except Exception:
                continue
            u = struct.unpack("<120H", pkt[0:240])
            packets.append((dt, u))
    packets.sort(key=lambda x: x[0])
    sessions = []
    cur = []; prev = None
    for dt, u in packets:
        if prev is not None and (dt - prev).total_seconds() > 1800:
            sessions.append(cur); cur = []
        cur.append((dt, u)); prev = dt
    if cur:
        sessions.append(cur)
    out = []
    for s in sessions:
        if len(s) < 60:
            continue
        start = s[0][0]; end = s[-1][0]
        dur_h = (end - start).total_seconds() / 3600.0
        def mean(idx):
            v = [u[idx] for _, u in s if u[idx] != 65535]
            return sum(v) / len(v) if v else 0.0
        # per-minute aggregates for curves, only for full nights
        per_min = []
        if dur_h >= 1.0:
            buckets = {}
            for dt, u in s:
                key = dt.strftime("%Y-%m-%dT%H:%M")
                buckets.setdefault(key, []).append(u)
            for key in sorted(buckets):
                us = buckets[key]
                def m2(idx):
                    v = [u[idx] for u in us if u[idx] != 65535]
                    return sum(v) / len(v) if v else 0.0
                per_min.append({"t": key, "ipap": round(m2(2)/2, 2), "epap": round(m2(3)/2, 2),
                                "tidal": round(m2(99), 1), "rr": round(m2(104), 1),
                                "f101": round(m2(101), 1), "f91": round(m2(91), 1)})
        out.append({"start": start.isoformat(), "end": end.isoformat(), "dur_h": round(dur_h, 2),
                    "ipap": round(mean(2)/2, 2), "epap": round(mean(3)/2, 2),
                    "tidal": round(mean(99), 1), "rr": round(mean(104), 1),
                    "f101": round(mean(101), 1), "f91": round(mean(91), 1),
                    "f98": round(mean(98), 1), "f105": round(mean(105), 1),
                    "per_min": per_min})
    full = [x for x in out if x["dur_h"] >= 1.0]
    return {"files": len(files), "packets": len(packets), "sessions": out, "full": full}

def read_usr_header(card):
    files = glob.glob(os.path.join(card, "*.USR"))
    if not files:
        return None
    d = open(files[0], "rb").read(256)
    serial = None
    # serial appears in header as ASCII A3119B03285; search only in first 256 bytes
    for i in range(len(d) - 11):
        chunk = d[i:i+11]
        try:
            txt = chunk.decode("ascii")
        except Exception:
            continue
        if txt.startswith("A3119") or txt.startswith("A31"):
            serial = txt
    has_g3 = b"G3-" in d
    return {"file": os.path.basename(files[0]), "size": os.path.getsize(files[0]),
            "serial_in_header": serial, "has_G3_marker": bool(has_g3),
            "note": "Only the 256-byte header was read. Personal content later in .USR was not read."}

def read_log_stats(card):
    files = glob.glob(os.path.join(card, "*.log"))
    if not files:
        return None
    size = os.path.getsize(files[0])
    types = Counter(); dates = []
    with open(files[0], "rb") as f:
        # sample first 200000 blocks max, in 512-byte steps, only header bytes
        for blk in range(0, min(size // 512, 200000)):
            f.seek(blk * 512)
            d = f.read(8)
            if len(d) < 8 or d[0] != 0xAA:
                continue
            types[d[1]] += 1
            # .log block date at bytes 2-7: year, month, day, hour, min, sec (validated for 2020 blocks)
            try:
                y = 2000 + d[2]; m = d[3]; dd = d[4]
                if 2020 <= y <= 2026 and 1 <= m <= 12 and 1 <= dd <= 31:
                    dates.append("%04d-%02d-%02d" % (y, m, dd))
            except Exception:
                pass
    return {"file": os.path.basename(files[0]), "size": size,
            "block_types": {hex(k): v for k, v in sorted(types.items())},
            "date_min": min(dates) if dates else None, "date_max": max(dates) if dates else None,
            "note": ".log is a software-operation journal, not therapy data. Only block headers were counted."}

def read_clarity_reference(folder):
    # Optional: clarity_reference.csv with columns date,ahi,hours,oa,ca,h,leak,press
    path = os.path.join(folder, "clarity_reference.csv")
    rows = []
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                rows.append(row)
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=None)
    ap.add_argument("--outdir", default=None)
    args = ap.parse_args()
    card = find_card(args.path)
    if not card:
        print("Card not found. Use --path /Volumes/NO NAME or a card copy.")
        return 2
    script_dir = os.path.dirname(os.path.abspath(__file__))
    outdir = args.outdir or os.path.join(script_dir, "output_v3")
    os.makedirs(outdir, exist_ok=True)
    print("Card:", card)
    idx, idx_file = read_idx(card)
    print("IDX records:", len(idx), idx_file)
    evt, evt_total, evt_file = read_evt(card)
    print("EVT records:", evt_total, evt_file, "groups:", len(evt))
    raw = read_raw_sessions(card)
    print("Raw files:", raw["files"], "packets:", raw["packets"], "sessions:", len(raw["sessions"]), "full nights:", len(raw["full"]))
    usr = read_usr_header(card)
    log = read_log_stats(card)
    clarity = read_clarity_reference(script_dir)
    print("Clarity reference rows:", len(clarity))
    rows = []
    for rec in idx:
        e = evt.get(rec["n"], {"n": 0, "types": {}, "a_max": 0, "small_types": 0})
        types = e["types"]
        sum123 = sum(types.get(t, 0) for t in (1, 2, 3))
        rows.append({"idx": rec["n"], "date": rec["date"], "evt_n": e["n"],
                     "evt_types": types, "evt_small": e["small_types"], "evt_a_max": e["a_max"],
                     "sum123": sum123})
    def esc(x):
        return html.escape(str(x))
    idx_rows_html = "".join(
        "<tr><td>%d</td><td>%s</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td></tr>" % (
            r["idx"], esc(r["date"]), r["evt_n"], esc(json.dumps(r["evt_types"], ensure_ascii=False)),
            r["sum123"], r["evt_small"], r["evt_a_max"]) for r in rows)
    full_rows_html = "".join(
        "<tr><td>%s</td><td>%s</td><td>%.2f</td><td>%.2f</td><td>%.2f</td><td>%.1f</td><td>%.1f</td><td>%.2f</td></tr>" % (
            esc(s["start"]), esc(s["end"]), s["dur_h"], s["ipap"], s["epap"], s["tidal"], s["rr"],
            (s["tidal"] * s["rr"] / 1000.0 if s["tidal"] and s["rr"] else 0.0))
        for s in raw["full"])
    clarity_rows_html = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(r.get("date", "")), esc(r.get("ahi", "")), esc(r.get("hours", "")),
            esc(r.get("oa", "")), esc(r.get("ca", "")), esc(r.get("h", "")),
            esc(r.get("leak", "")), esc(r.get("press", ""))) for r in clarity) or "<tr><td colspan=8>No clarity_reference.csv found. Put the Clarity export per-night table in clarity_reference.csv next to this script and re-run.</td></tr>"
    full = raw["full"]
    latest = full[-1] if full else None
    if latest:
        latest_mv = latest["tidal"] * latest["rr"] / 1000.0 if latest["tidal"] and latest["rr"] else 0.0
        latest_html = ("<dl class=\"kv\"><dt>开始</dt><dd>%s</dd><dt>结束</dt><dd>%s</dd>"
                       "<dt>时长</dt><dd>%.2f 小时</dd><dt>IPAP 均值</dt><dd>%.2f cmH2O</dd>"
                       "<dt>EPAP 均值</dt><dd>%.2f cmH2O</dd><dt>潮气量均值</dt><dd>%.1f ml</dd>"
                       "<dt>呼吸频率均值</dt><dd>%.1f 次/分</dd><dt>分钟通气量（推算）</dt><dd>%.2f L/min</dd></dl>"
                       "<p>这是波形包里最后一个 1 小时以上完整夜。Clarity 夜标签与波形夜起始日期可能差 1 天，见第七节对齐提醒，不要只按日期硬对。</p>") % (
            esc(latest["start"]), esc(latest["end"]), latest["dur_h"], latest["ipap"], latest["epap"],
            latest["tidal"], latest["rr"], latest_mv)
    else:
        latest_html = "<p>没有 1 小时以上完整夜。</p>"
    curves = [{"start": s["start"], "end": s["end"], "dur_h": s["dur_h"], "ipap": s["ipap"], "epap": s["epap"],
               "tidal": s["tidal"], "rr": s["rr"],
               "mv": round(s["tidal"] * s["rr"] / 1000.0, 2) if s["tidal"] and s["rr"] else 0.0,
               "per_min": s["per_min"]} for s in full]
    gen_date = datetime.now().strftime("%Y-%m-%d %H:%M")
    hero_meta = ("<span>版本 v3</span><span>生成 %s</span><span>IDX %d 条</span><span>EVT %d 条 / %d 组</span>"
                 "<span>波形包 %d 个</span><span>完整夜 %d 夜</span>") % (
        esc(gen_date), len(idx), evt_total, len(evt), raw["packets"], len(full))
    doc = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>BMC RESmart 全卡分析报告</title>
<style>
:root{--bg:#f5f7fa;--fg:#0f172a;--mut:#64748b;--line:#e2e8f0;--blue:#2563eb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);line-height:1.7;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1240px;margin:0 auto;padding:40px 20px 60px}
.layout{display:grid;grid-template-columns:280px 1fr;gap:18px;align-items:start}
.sidebar{position:sticky;top:16px;display:flex;flex-direction:column;gap:18px}
.sidebar .card{padding:18px 20px}
.nav a{display:block;padding:5px 0;color:var(--blue);text-decoration:none;font-size:13px}
@media(max-width:900px){.layout{grid-template-columns:1fr}.sidebar{position:static}}
.hero{background:linear-gradient(135deg,#1e3a8a,#2563eb 55%,#0ea5e9);color:#fff;border-radius:16px;padding:30px 32px;margin-bottom:24px}
.hero h1{margin:0 0 8px;font-size:27px;text-align:center}
.hero p{text-align:center;margin:0;font-size:14px;opacity:.93}
.hero .meta{display:flex;gap:16px;flex-wrap:wrap;margin-top:12px;font-size:13px;justify-content:center}
.hero .meta span{background:rgba(255,255,255,.15);padding:4px 10px;border-radius:999px}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:22px 24px}
.card h2{margin:0 0 6px;font-size:17px;color:var(--blue)}
.card p{margin:0 0 10px;font-size:13px;color:var(--mut)}
.tag{display:inline-block;font-size:11px;padding:2px 9px;border-radius:999px;background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe;margin-right:6px}
.section{background:#fff;border:1px solid var(--line);border-radius:14px;padding:22px 24px;margin-top:24px}
.section h3{margin:0 0 14px;font-size:16px;color:var(--blue)}
.kv{display:grid;grid-template-columns:150px 1fr;gap:8px 16px;font-size:13px}
.kv dt{color:var(--mut)}
.kv dd{margin:0}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}
td,th{border:1px solid var(--line);padding:4px 6px;text-align:left}
.warn{background:#fff7e6;border:1px solid #f0c36d;padding:12px;border-radius:10px;font-size:13px}
canvas{width:100%;height:260px;border:1px solid var(--line)}
select{font-size:14px;padding:4px 8px}
footer{margin-top:24px;font-size:12px;color:var(--mut);text-align:center}
</style></head><body><div class="wrap">
<div class="hero"><h1>BMC RESmart 全卡分析报告</h1>
<p>G3 A20 · APAP · 卡上解码与 Clarity 对照 · 只读卡，不写卡</p>
<div class="meta">__HERO_META__</div></div>
<div class="layout"><div class="sidebar">
<div class="card"><h2>最新一晚</h2><p>波形包里最后一个 1 小时以上完整夜</p>__LATEST__</div>
<div class="card"><h2>模式与口径</h2>
<p><span class="tag">设备</span>BMC G3 A20 · APAP</p>
<p><span class="tag">设置快照</span>Clarity 设置快照（2026-10-28 导出时快照，可能已过期）：压力 6.5-16 cmH2O，鼻枕，Reslex 2 级，湿度 6，爬坡 5 分钟，SmartStart / SmartStop 开。</p>
<p><span class="tag">AHI 口径</span>分子 = .evt 类型 1+2+3，类型 11 不计；分母 = 波形包数除以 3600。此口径为 2026-10-28 统计对照结果，仍有未解夜，见第七节。</p>
<p><span class="tag">漏气</span>卡上没有现成漏气字段，本页不输出漏气曲线。</p>
<p><span class="tag">事件分工</span>候选：1=中枢、2=阻塞、3=低通气，未获官方对照确认，不得写死。</p></div>
<div class="card"><h2>区块导航</h2><div class="nav">
<a href="#daily">一、每日分析解读</a><a href="#curves">二、数据图形分析说明</a>
<a href="#sessions">三、会话总表</a><a href="#nights">四、波形完整夜总表</a>
<a href="#clarity">五、Clarity 参考</a><a href="#files">六、文件解码</a>
<a href="#check">七、Clarity 全表统计对照结论</a><a href="#unsolved">八、未解部分</a>
</div></div></div>
<div><div class="section" id="daily"><h3>一、每日分析解读 · 选择夜晚</h3>
<p><select id="nightSel2"></select></p><div id="nightInfo"></div>
<p>说明：这里列的是波形包完整夜，不是 Clarity 夜标签。Clarity 夜标签与波形夜起始日期可能差 1 天，同日还可能有两组或短片段，顺序对照比日期对照更稳，见第七节。</p></div>
<div class="section" id="curves"><h3>二、数据图形分析说明 · 选择夜晚与指标</h3>
<p><select id="nightSel"></select> <select id="metricSel">
<option value="ipap">IPAP</option><option value="epap">EPAP</option>
<option value="tidal">潮气量</option><option value="rr">呼吸频率</option>
<option value="mv">分钟通气量（推算）</option></select></p>
<canvas id="cv" width="1000" height="260"></canvas>
<p>说明：曲线为每分钟均值；时间缺口超过 5 分钟处断开，不连线。分钟通气量为潮气量乘呼吸频率除以 1000 推算而来，不是卡上现成字段。.evt 事件的 A 字段是计数器、不是墙钟时间，对不到曲线时间轴上，所以本页不画事件刻度，硬画就是假的。漏气没有现成字段，不画漏气曲线。</p></div>
<div class="warn"><b>仅供个人回顾参考，不用于诊断，不提示调压，调压请问医生。数值可能有误差，医疗或保险决定以设备或官方软件为准。</b></div>
</div></div>
<div class="section" id="sessions"><h3>三、会话总表 · 370 组</h3>
<p>小类型列仍为 1/2/3/11 之和，不是 AHI 分子；AHI 分子一列为 1+2+3 之和，见第七节。</p>
<table><tr><th>#</th><th>IDX 日期时间</th><th>EVT 记录数</th><th>EVT 类型分布</th><th>AHI 分子（1+2+3）</th><th>小类型（1/2/3/11）</th><th>EVT A 最大值</th></tr>__IDX_ROWS__</table></div>
<div class="section" id="nights"><h3>四、波形完整夜总表 · 106 夜</h3>
<p>1 小时以上完整夜，原始包按分钟聚合；分钟通气量一列为推算值。</p>
<table><tr><th>开始</th><th>结束</th><th>时长（小时）</th><th>IPAP 均值</th><th>EPAP 均值</th><th>潮气量均值（ml）</th><th>呼吸频率均值</th><th>分钟通气量推算（L/min）</th></tr>__FULL_ROWS__</table></div>
<div class="section" id="clarity"><h3>五、Clarity 参考（用户提供的导出，非卡上解码）</h3>
<p>下面这张表只有在脚本旁边放了 clarity_reference.csv 时才有数据。Clarity 的 AHI 口径是事件总数除以治疗小时，与某些工具排除摘面罩时间的算法不同。</p>
<table><tr><th>日期</th><th>AHI</th><th>小时</th><th>阻塞</th><th>中枢</th><th>低通气</th><th>漏气</th><th>压力均值</th></tr>__CLARITY_ROWS__</table></div>
<div class="section" id="files"><h3>六、文件解码 · 每个文件解开了什么、没解开什么</h3>
<table><tr><th>文件</th><th>已验证</th><th>未验证 / 不做</th></tr>
<tr><td>.000-.029 原始波形</td><td>每秒 1 包；IPAP=uint16[2]/2，EPAP=uint16[3]/2（cmH2O）；潮气量字段 uint16[99]（毫升，平均约 430，与 Clarity 最近一晚 0.43 升吻合）；呼吸频率 uint16[104]（次/分）；25Hz 压力字段 4-28、29-53，25Hz 流量字段 54-78（有符号流量，负值会绕回 65535 附近）</td><td>字段 91、98、101、105 等未定名：均值与 Clarity 漏气不稳定对应，不当作漏气。字段 1（恒约 322）不当作 Reslex。</td></tr>
<tr><td>.idx 每会话记录</td><td>每条 512 字节，首 AAAA，序号 uint16，日期字节 4-6（年-2000、月、日），时间字节 8-10（时、分、秒），共 370 条，日期与 EVT 分组一一对应。64 字节之后 64-384 字节在全部记录里完全相同，是固定模板，不是每夜数据；384-512 全为 FF。</td><td>头 64 字节里除日期时间序号外的数值（偏移量/计数器类）未可靠对应到时长、AHI、漏气，不用它们算 AHI。</td></tr>
<tr><td>.evt 事件/汇总记录</td><td>每条 32 字节，首 AAAA，分组 uint16[1] 为 1-370，类型 uint16[2] 取值 1、2、3、4、5、7、8、11；A=uint16[4]、B=uint16[6]、C=uint16[9]。类型 1、2、3、11 的 B 多为 10-18（秒级时长，像单次事件时长），类型 4 的 B 多为 600，类型 7 的 B 常为 14400。2026-10-28 更新：类型 1+2+3 之和在单组对照中 270/349 夜等于 Clarity 总事件数（77%），最近 13 夜顺序对照 12/13 完全相等，仅 2023-08-17 差 1 个；类型 11 不计入 AHI 分子。</td><td>类型分工候选为 1=中枢、2=阻塞、3=低通气（2021-07-18 与 2023-08-25 分项完全相等，08-17 阻塞差 1 个），未获官方对照确认前不得写死。按上游开源项目说法，AHI 判定似乎在 BMC 软件里做，不在机器上。</td></tr>
<tr><td>.usr 用户文件</td><td>只读了前 256 字节头：含序列号与 G3- 标记，文件大小 1268377 字节。</td><td>头之后的内容含个人信息与软件写回的汇总，未读、未解、不展示。</td></tr>
<tr><td>.log 软件操作日志</td><td>512 字节一块，首字节 AA，块类型分布与块日期范围已统计；块里含文件名（如 .idx、.evt）和软件操作记录。</td><td>不是治疗数据，不从 .log 算 AHI、漏气、时长。</td></tr>
</table></div>
<div class="section" id="check"><h3>七、Clarity 全表统计对照结论（2026-10-28）</h3>
<p>来源：Clarity PDF 逐夜表 353 夜（2020-05-07 至 2023-08-25）对卡上 .evt 370 组、原始包 1,966,080 包。统计方法：先按 idx 日期减 1 天对 Clarity 日期做单组对照，再按顺序对照最近 13 夜。</p>
<ul><li>分子：AHI 分子 = 类型 1 + 类型 2 + 类型 3 的个数，类型 11 不计。单组对照 270/349 夜（77%）等于 Clarity 总事件数；最近 13 夜卡上和为 8、8、14、14、27、6、11、8、11、8、15、6、5，Clarity 为 8、8、14、14、26、6、11、8、11、8、15、6、5，仅 2023-08-17 差 1 个。</li>
<li>分工候选（未确认）：类型 1 = 中枢，类型 2 = 阻塞，类型 3 = 低通气。2021-07-18 与 2023-08-25 分项完全相等，08-17 阻塞差 1 个；.evt 记录里 A 字段高位为 1 的那条只是 32 位计数器跨过 65536，不是排除对象。</li>
<li>分母：包数除以 3600（每包约 1 秒）多数夜与 Clarity 时长差在 0.02 小时内，但 2023-08-17、08-19、08-25 三夜 Clarity 还短 0.50 至 1.25 小时，包间缺口合计仅 0.12 至 0.17 小时，说明连续包段内另有排除规则未解。</li>
<li>结论：AHI =（类型 1+2+3）除以（包数除以 3600）在多数夜可复现 Clarity AHI 到小数点后一位，但在上述 3 夜会算高；在排除规则查清、阻塞差 1 个的原因查清之前，本代码仍不直接输出 AHI，仍以 Clarity 参考为准。</li>
<li>对齐提醒：不要只按日历日期硬对，idx 日期、包会话起始日期与 Clarity 夜标签存在 1 天左右错位，同日还可能有两组或短片段，顺序对照比日期对照更稳。</li></ul></div>
<div class="section" id="unsolved"><h3>八、未解部分</h3>
<ul><li>EVT 类型 1/2/3/4/5/7/8/11 的确切含义，需要 PAP Link 官方软件的对照输出或临床手册，不能靠计数猜；分工候选见第七节。</li>
<li>IDX 头 64 字节里的偏移量/计数器，需要与 .evt/.000 的指针关系逐组验证，不能直接当作时长或事件数。</li>
<li>.usr 头之后的汇总区未读（个人信息），如需用它，必须先由用户确认范围并只取汇总字段。</li>
<li>漏气：原始包里没有一个字段能稳定对应 Clarity 漏气，Clarity 的漏气很可能是从 25Hz 流量基线算出来的，不是卡上现成字段。</li>
<li>分母多排除 0.50 至 1.25 小时的三夜规则未解；阻塞差 1 个的排除规则未解。</li></ul></div>
<footer>版本 v3 · 生成 __GEN_DATE__ · 由 generate_bmc_report_v3.py 生成 · 卡路径 __CARD__<br>仅供个人回顾参考，不用于诊断，不提示调压，医疗或保险决定以设备或官方软件为准。</footer>
</div>
<script>var curves=__CURVES_JSON__;
var sel=document.getElementById('nightSel');var sel2=document.getElementById('nightSel2');
curves.forEach(function(c,i){var o=document.createElement('option');o.value=i;o.text=c.start;sel.appendChild(o);var o2=document.createElement('option');o2.value=i;o2.text=c.start;sel2.appendChild(o2);});
sel.value=curves.length-1;sel2.value=curves.length-1;
function showNight(){var c=curves[sel2.value];if(!c)return;document.getElementById('nightInfo').innerHTML='<dl class="kv"><dt>开始</dt><dd>'+c.start+'</dd><dt>结束</dt><dd>'+c.end+'</dd><dt>时长</dt><dd>'+c.dur_h+' 小时</dd><dt>IPAP 均值</dt><dd>'+c.ipap+' cmH2O</dd><dt>EPAP 均值</dt><dd>'+c.epap+' cmH2O</dd><dt>潮气量均值</dt><dd>'+c.tidal+' ml</dd><dt>呼吸频率均值</dt><dd>'+c.rr+' 次/分</dd><dt>分钟通气量（推算）</dt><dd>'+c.mv+' L/min</dd></dl>';}
function draw(){var c=curves[sel.value];if(!c)return;var m=document.getElementById('metricSel').value;
var cv=document.getElementById('cv');var ctx=cv.getContext('2d');ctx.clearRect(0,0,1000,260);
var pts=c.per_min.map(function(p){return {t:new Date(p.t),v:p[m]};});
var vals=pts.map(function(p){return p.v;});var mx=Math.max.apply(null,vals);var mn=Math.min.apply(null,vals);
ctx.beginPath();var started=false;
pts.forEach(function(p,i){var x=i/(Math.max(1,pts.length-1))*1000;var y=250-(p.v-mn)/(mx-mn||1)*230;
if(i>0 && (p.t-pts[i-1].t)>5*60000){started=false;}
if(!started){ctx.moveTo(x,y);started=true;}else{ctx.lineTo(x,y);}});
ctx.stroke();
ctx.fillText(m+' min '+mn.toFixed(1)+' max '+mx.toFixed(1)+' n='+pts.length,10,20);}
sel.onchange=draw;sel2.onchange=showNight;document.getElementById('metricSel').onchange=draw;showNight();draw();
</script></body></html>"""
    doc = doc.replace("__HERO_META__", hero_meta).replace("__LATEST__", latest_html)
    doc = doc.replace("__IDX_ROWS__", idx_rows_html).replace("__FULL_ROWS__", full_rows_html)
    doc = doc.replace("__CLARITY_ROWS__", clarity_rows_html).replace("__CURVES_JSON__", json.dumps(curves, ensure_ascii=False))
    doc = doc.replace("__GEN_DATE__", esc(gen_date)).replace("__CARD__", esc(card))
    out_html = os.path.join(outdir, "bmc_report.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(doc)
    print("Wrote:", out_html)
    with open(os.path.join(outdir, "sessions_v3.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["idx", "date", "evt_n", "evt_types", "sum123", "evt_small", "evt_a_max"])
        w.writeheader()
        for r in rows:
            w.writerow({"idx": r["idx"], "date": r["date"], "evt_n": r["evt_n"],
                        "evt_types": json.dumps(r["evt_types"], ensure_ascii=False),
                        "sum123": r["sum123"], "evt_small": r["evt_small"], "evt_a_max": r["evt_a_max"]})
    with open(os.path.join(outdir, "raw_full_nights_v3.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["start", "end", "dur_h", "ipap", "epap", "tidal", "rr", "mv_derived"])
        w.writeheader()
        for s in full:
            w.writerow({"start": s["start"], "end": s["end"], "dur_h": s["dur_h"], "ipap": s["ipap"],
                        "epap": s["epap"], "tidal": s["tidal"], "rr": s["rr"],
                        "mv_derived": round(s["tidal"] * s["rr"] / 1000.0, 2) if s["tidal"] and s["rr"] else 0.0})
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
