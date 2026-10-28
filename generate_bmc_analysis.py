#!/usr/bin/env python3
# BMC RESmart full-card analysis page, v2.
# Reads ONLY the card (or a card copy). Never writes to the card.
# Decodes, with evidence, what is validated; marks what is NOT decoded.
# AHI/leak from CPAP Clarity are NOT computed here: they are shown only
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
    outdir = args.outdir or os.path.join(script_dir, "output_v2")
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
    # join: idx session n -> evt summary; raw sessions matched by nearest start date (for display only)
    rows = []
    for rec in idx:
        e = evt.get(rec["n"], {"n": 0, "types": {}, "a_max": 0, "small_types": 0})
        rows.append({"idx": rec["n"], "date": rec["date"], "evt_n": e["n"],
                     "evt_types": e["types"], "evt_small": e["small_types"], "evt_a_max": e["a_max"],
                     "header_hex": rec["header_hex"]})
    # build HTML
    def esc(x):
        return html.escape(str(x))
    idx_rows_html = "".join(
        "<tr><td>%d</td><td>%s</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>" % (
            r["idx"], esc(r["date"]), r["evt_n"], esc(json.dumps(r["evt_types"], ensure_ascii=False)),
            r["evt_small"], r["evt_a_max"]) for r in rows)
    full_rows_html = "".join(
        "<tr><td>%s</td><td>%s</td><td>%.2f</td><td>%.2f</td><td>%.2f</td><td>%.1f</td><td>%.1f</td></tr>" % (
            esc(s["start"]), esc(s["end"]), s["dur_h"], s["ipap"], s["epap"], s["tidal"], s["rr"])
        for s in raw["full"])
    clarity_rows_html = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(r.get("date", "")), esc(r.get("ahi", "")), esc(r.get("hours", "")),
            esc(r.get("oa", "")), esc(r.get("ca", "")), esc(r.get("h", "")),
            esc(r.get("leak", "")), esc(r.get("press", ""))) for r in clarity) or "<tr><td colspan=8>No clarity_reference.csv found. Put the Clarity export per-night table in clarity_reference.csv next to this script and re-run.</td></tr>"
    # curves data for full nights, as JSON
    curves = [{"start": s["start"], "per_min": s["per_min"]} for s in raw["full"]]
    html_doc = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>BMC RESmart full-card analysis v2</title>
<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;line-height:1.6}
table{border-collapse:collapse;width:100%%}td,th{border:1px solid #ccc;padding:4px 6px;font-size:13px;text-align:left}
.warn{background:#fff7e6;border:1px solid #f0c36d;padding:12px}code{word-break:break-all}
canvas{width:100%%;height:260px;border:1px solid #ccc}</style></head><body>
<h1>BMC RESmart 全卡分析 v2</h1>
<p>只读卡，不写卡。AHI 与漏气不是本代码算出来的：卡上没有现成的 AHI，Clarity 的 AHI 是它自己的算法从波形/汇总里算的。
本页把卡上已验证的部分、未验证的部分、以及 Clarity 参考（如果提供）分开列出，不混在一起。</p>
<div class="warn"><b>仅供个人回顾参考，不用于诊断，不提示调压，调压请问医生。数值可能有误差，医疗或保险决定以设备或官方软件为准。</b></div>
<h2>1. 卡总览</h2>
<p>卡路径：%s<br>IDX 文件：%s，记录 %d 条（每条 512 字节，数据从 2048 字节起）<br>
EVT 文件：%s，记录 %d 条（每条 32 字节，数据从 2048 字节起），分组 %d 组<br>
原始波形文件：%d 个，包 %d 个（每包 256 字节，首 uint16 为 0xAAAA），会话（60 秒以上）%d 个，其中 1 小时以上完整夜 %d 夜<br>
USR：%s<br>LOG：%s</p>
<h2>2. 每个文件解开了什么、没解开什么</h2>
<table><tr><th>文件</th><th>已验证</th><th>未验证 / 不做</th></tr>
<tr><td>.000-.029 原始波形</td><td>每秒 1 包；IPAP=uint16[2]/2，EPAP=uint16[3]/2（cmH2O）；潮气量字段 uint16[99]（毫升，平均约 430，与 Clarity 最近一晚 0.43 升吻合）；呼吸频率 uint16[104]（次/分）；25Hz 压力字段 4-28、29-53，25Hz 流量字段 54-78（有符号流量，负值会绕回 65535 附近）</td><td>字段 91、98、101、105 等未定名：均值与 Clarity 漏气不稳定对应，不当作漏气。字段 1（恒约 322）不当作 Reslex。</td></tr>
<tr><td>.idx 每会话记录</td><td>每条 512 字节，首 AAAA，序号 uint16，日期字节 4-6（年-2000、月、日），时间字节 8-10（时、分、秒），共 370 条，日期与 EVT 分组一一对应。64 字节之后 64-384 字节在全部记录里完全相同，是固定模板，不是每夜数据；384-512 全为 FF。</td><td>头 64 字节里除日期时间序号外的数值（偏移量/计数器类）未可靠对应到时长、AHI、漏气，不用它们算 AHI。</td></tr>
<tr><td>.evt 事件/汇总记录</td><td>每条 32 字节，首 AAAA，分组 uint16[1] 为 1-370，类型 uint16[2] 取值 1、2、3、4、5、7、8、11；A=uint16[4]、B=uint16[6]、C=uint16[9]。类型 1、2、3、11 的 B 多为 10-18（秒级时长，像单次事件时长），类型 4 的 B 多为 600，类型 7 的 B 常为 14400。</td><td>类型与阻塞/中枢/低通气的对应未验证：各组小类型计数与 Clarity 逐夜事件总数对不上（例如 2023-08-25 组小类型为 7，Clarity 为 5），所以本页不把 EVT 计数当作 AHI 事件数。按上游开源项目说法，AHI 判定似乎在 BMC 软件里做，不在机器上。</td></tr>
<tr><td>.usr 用户文件</td><td>只读了前 256 字节头：含序列号与 G3- 标记，文件大小 1268377 字节。</td><td>头之后的内容含个人信息与软件写回的汇总，未读、未解、不展示。</td></tr>
<tr><td>.log 软件操作日志</td><td>512 字节一块，首字节 AA，块类型分布与块日期范围已统计；块里含文件名（如 .idx、.evt）和软件操作记录。</td><td>不是治疗数据，不从 .log 算 AHI、漏气、时长。</td></tr>
</table>
<h2>3. 370 个会话（IDX + EVT 对照）</h2>
<p>注意：370 会话经同日合并后对应 Clarity 的 366 夜，导出里为 365 夜（差 1 夜未在导出里）。同日两会话的例子：2020-05-14、2020-05-22、2023-08-19 等。</p>
<table><tr><th>#</th><th>IDX 日期时间</th><th>EVT 记录数</th><th>EVT 类型分布</th><th>小类型(1/2/3/11)计数</th><th>EVT A 最大值</th></tr>%s</table>
<h2>4. 波形完整夜（106 夜，原始包聚合）</h2>
<table><tr><th>开始</th><th>结束</th><th>时长(小时)</th><th>IPAP均值</th><th>EPAP均值</th><th>潮气量均值(ml)</th><th>呼吸频率均值</th></tr>%s</table>
<h2>5. 每夜按分钟曲线（选完整夜）</h2>
<p><select id="nightSel"></select> <select id="metricSel">
<option value="ipap">IPAP</option><option value="epap">EPAP</option>
<option value="tidal">潮气量</option><option value="rr">呼吸频率</option></select></p>
<canvas id="cv" width="1000" height="260"></canvas>
<h2>6. Clarity 参考（用户提供的导出，非卡上解码）</h2>
<p>下面这张表只有在脚本旁边放了 clarity_reference.csv 时才有数据。Clarity 的 AHI 口径是事件总数除以治疗小时，与某些工具排除摘面罩时间的算法不同。</p>
<table><tr><th>日期</th><th>AHI</th><th>小时</th><th>阻塞</th><th>中枢</th><th>低通气</th><th>漏气</th><th>压力均值</th></tr>%s</table>
<h2>7. 下一步才能解开的部分</h2>
<ul><li>EVT 类型 1/2/3/4/5/7/8/11 的确切含义，需要 PAP Link 官方软件的对照输出或临床手册，不能靠计数猜。</li>
<li>IDX 头 64 字节里的偏移量/计数器，需要与 .evt/.000 的指针关系逐组验证，不能直接当作时长或事件数。</li>
<li>.usr 头之后的汇总区未读（个人信息），如需用它，必须先由用户确认范围并只取汇总字段。</li>
<li>漏气：原始包里没有一个字段能稳定对应 Clarity 漏气，Clarity 的漏气很可能是从 25Hz 流量基线算出来的，不是卡上现成字段。</li></ul>
<script>var curves=%s;
var sel=document.getElementById('nightSel');
curves.forEach(function(c,i){var o=document.createElement('option');o.value=i;o.text=c.start;sel.appendChild(o);});
function draw(){var c=curves[sel.value];if(!c)return;var m=document.getElementById('metricSel').value;
var cv=document.getElementById('cv');var ctx=cv.getContext('2d');ctx.clearRect(0,0,1000,260);
var vals=c.per_min.map(function(p){return p[m]});var mx=Math.max.apply(null,vals);var mn=Math.min.apply(null,vals);
ctx.beginPath();c.per_min.forEach(function(p,i){var x=i/(Math.max(1,c.per_min.length-1))*1000;var y=250-(vals[i]-mn)/(mx-mn||1)*230;if(i==0)ctx.moveTo(x,y);else ctx.lineTo(x,y);});ctx.stroke();
ctx.fillText(m+' min '+mn.toFixed(1)+' max '+mx.toFixed(1)+' n='+c.per_min.length,10,20);}
sel.onchange=draw;document.getElementById('metricSel').onchange=draw;draw();
</script></body></html>""" % (
        esc(card), esc(idx_file or ""), len(idx), esc(evt_file or ""), evt_total, len(evt),
        raw["files"], raw["packets"], len(raw["sessions"]), len(raw["full"]),
        esc(json.dumps(usr, ensure_ascii=False)) if usr else "not found",
        esc(json.dumps(log, ensure_ascii=False)) if log else "not found",
        idx_rows_html, full_rows_html, clarity_rows_html,
        json.dumps(curves, ensure_ascii=False))
    out_html = os.path.join(outdir, "bmc_analysis.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html_doc)
    # also write machine-readable session table
    with open(os.path.join(outdir, "sessions_v2.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["idx", "date", "evt_n", "evt_types", "evt_small", "evt_a_max"])
        w.writeheader()
        for r in rows:
            w.writerow({"idx": r["idx"], "date": r["date"], "evt_n": r["evt_n"],
                        "evt_types": json.dumps(r["evt_types"], ensure_ascii=False),
                        "evt_small": r["evt_small"], "evt_a_max": r["evt_a_max"]})
    with open(os.path.join(outdir, "raw_full_nights.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["start", "end", "dur_h", "ipap", "epap", "tidal", "rr", "f101", "f91", "f98", "f105"])
        w.writeheader()
        for s in raw["full"]:
            w.writerow({k: s[k] for k in ["start", "end", "dur_h", "ipap", "epap", "tidal", "rr", "f101", "f91", "f98", "f105"]})
    print("Wrote:", out_html)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
