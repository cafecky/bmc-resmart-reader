#!/usr/bin/env python3
# BMC RESmart GII complete reader, v1.0
# Reads a BMC RESmart SD card (raw *.000-*.029 packets, 256 bytes each),
# builds per-night sessions, per-minute curves, and a self-contained HTML report.
# Only the Python standard library is used. The card is read, never written.
# Health data (report output) is NOT meant for GitHub; only this code is.
# BMC raw format notes (reverse-engineered, NOT an official spec):
#   - Each packet is 256 bytes, first uint16 is 0xAAAA.
#   - IPAP = uint16[2] / 2.0 cmH2O, EPAP = uint16[3] / 2.0 cmH2O.
#   - Tidal volume = uint16[99] (ml, guess; 0xFFFF = invalid).
#   - Respiration rate = uint16[104] (breaths/min; 0xFFFF or 0 = invalid).
#   - Last 8 bytes are timestamp: uint16 year, then month, day, hour, minute, second, unknown.
#   - AHI / leak are NOT in these raw packets. The .evt file (32-byte records)
#     is counted but NOT decoded for events in v1.0; do not use this report for diagnosis.
import argparse
import csv
import datetime
import glob
import html
import json
import os
import statistics
import struct
import sys

VERSION = "v1.0"
PACKET_SIZE = 256
GAP_SECONDS = 1800


def find_card(explicit=None):
    if explicit:
        return explicit
    candidates = []
    for vol in sorted(glob.glob("/Volumes/*")):
        raws = sorted(glob.glob(os.path.join(vol, "*.[0-9][0-9][0-9]")))
        if raws:
            candidates.append((len(raws), vol))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def card_root_and_files(card_path):
    raws = sorted(glob.glob(os.path.join(card_path, "*.[0-9][0-9][0-9]")))
    roots = {}
    for f in raws:
        root = os.path.basename(f).rsplit(".", 1)[0]
        roots[root] = roots.get(root, 0) + 1
    root = max(roots, key=roots.get) if roots else ""
    return root, [f for f in raws if os.path.basename(f).startswith(root + ".")]


def parse_card(card_path):
    root, files = card_root_and_files(card_path)
    minutes = {}
    total_packets = 0
    valid_packets = 0
    for fn in files:
        with open(fn, "rb") as fh:
            data = fh.read()
        n = len(data) // PACKET_SIZE
        total_packets += n
        for i in range(n):
            pkt = data[i * PACKET_SIZE:(i + 1) * PACKET_SIZE]
            if struct.unpack("<H", pkt[0:2])[0] != 0xAAAA:
                continue
            valid_packets += 1
            y, mo, d, h, mi, s, _u = struct.unpack("<HBBBBBB", pkt[248:256])
            try:
                dt = datetime.datetime(y, mo, d, h, mi, s)
            except ValueError:
                continue
            vals = struct.unpack("<106H", pkt[0:212])
            ipap = vals[2] / 2.0
            epap = vals[3] / 2.0
            tidal = vals[99] if vals[99] != 65535 else None
            resp = vals[104] if vals[104] not in (65535, 0) else None
            minute = dt.replace(second=0)
            m = minutes.get(minute)
            if m is None:
                m = {"packets": 0, "ipap": 0.0, "epap": 0.0,
                     "tidal": 0.0, "tidal_n": 0, "resp": 0.0, "resp_n": 0}
                minutes[minute] = m
            m["packets"] += 1
            m["ipap"] += ipap
            m["epap"] += epap
            if tidal is not None:
                m["tidal"] += tidal
                m["tidal_n"] += 1
            if resp is not None:
                m["resp"] += resp
                m["resp_n"] += 1
    return root, files, minutes, total_packets, valid_packets


def build_sessions(minutes):
    ordered = sorted(minutes.keys())
    sessions = []
    cur = []
    prev = None
    for minute in ordered:
        if prev is not None and (minute - prev).total_seconds() > GAP_SECONDS:
            sessions.append(cur)
            cur = []
        cur.append(minute)
        prev = minute
    if cur:
        sessions.append(cur)
    out = []
    for mins in sessions:
        packets = sum(minutes[m]["packets"] for m in mins)
        ipap = sum(minutes[m]["ipap"] for m in mins) / packets if packets else 0
        epap = sum(minutes[m]["epap"] for m in mins) / packets if packets else 0
        tn = sum(minutes[m]["tidal_n"] for m in mins)
        tidal = sum(minutes[m]["tidal"] for m in mins) / tn if tn else None
        rn = sum(minutes[m]["resp_n"] for m in mins)
        resp = sum(minutes[m]["resp"] for m in mins) / rn if rn else None
        start = mins[0]
        end = mins[-1] + datetime.timedelta(minutes=1)
        out.append({
            "start": start.isoformat(), "end": end.isoformat(),
            "packets": packets, "dur_h": round(packets / 3600.0, 2),
            "span_h": round((end - start).total_seconds() / 3600.0, 2),
            "ipap_mean": round(ipap, 2), "epap_mean": round(epap, 2),
            "tidal_mean": round(tidal, 1) if tidal is not None else None,
            "resp_mean": round(resp, 2) if resp is not None else None,
            "minutes": [m.isoformat() for m in mins],
        })
    return out


def count_evt(card_path, root):
    evt_path = os.path.join(card_path, root + ".evt")
    if not os.path.exists(evt_path):
        return None
    data = open(evt_path, "rb").read()
    recs = 0
    groups = set()
    for off in range(2048, len(data) - 31, 32):
        r = data[off:off + 32]
        if r[0:2] == b"\xaa\xaa":
            recs += 1
            groups.add(struct.unpack("<H", r[2:4])[0])
    return {"path": evt_path, "size": len(data), "records": recs, "groups": len(groups)}


def monthly_table(full):
    table = {}
    for s in full:
        key = s["start"][:7]
        t = table.setdefault(key, {"nights": 0, "hours": 0.0, "ipap": []})
        t["nights"] += 1
        t["hours"] += s["dur_h"]
        t["ipap"].append(s["ipap_mean"])
    rows = []
    for key in sorted(table):
        t = table[key]
        rows.append((key, t["nights"], round(t["hours"], 1),
                     round(statistics.mean(t["ipap"]), 2) if t["ipap"] else None))
    return rows


def fmt(x, nd=2):
    if x is None:
        return "-"
    return str(round(x, nd))


def build_html(summary, full, brief, monthly, minutes, evt_info):
    # Per-minute curves, full sessions only, down to minute means.
    curves = {}
    for idx, s in enumerate(full):
        pts = []
        for mstr in s["minutes"]:
            m = datetime.datetime.fromisoformat(mstr)
            d = minutes[m]
            n = d["packets"]
            pts.append([
                mstr,
                round(d["ipap"] / n, 2) if n else None,
                round(d["epap"] / n, 2) if n else None,
                round(d["tidal"] / d["tidal_n"], 1) if d["tidal_n"] else None,
                round(d["resp"] / d["resp_n"], 2) if d["resp_n"] else None,
            ])
        curves[str(idx)] = {"start": s["start"], "end": s["end"], "points": pts}
    last = full[-1] if full else None
    prev = full[-2] if len(full) >= 2 else None
    rows_html = ""
    for i, s in enumerate(full):
        rows_html += ("<tr><td>%d</td><td>%s</td><td>%s</td><td>%.2f</td>"
                      "<td>%.2f</td><td>%.2f</td><td>%s</td><td>%s</td></tr>\n" % (
                          i + 1, html.escape(s["start"]), html.escape(s["end"]),
                          s["dur_h"], s["ipap_mean"], s["epap_mean"],
                          fmt(s["tidal_mean"], 1), fmt(s["resp_mean"], 2)))
    monthly_html = ""
    for key, nights, hours, ipap in monthly:
        monthly_html += "<tr><td>%s</td><td>%d</td><td>%.1f</td><td>%s</td></tr>\n" % (
            html.escape(key), nights, hours, fmt(ipap, 2))
    evt_html = "未找到 .evt 文件。"
    if evt_info:
        evt_html = ("文件 %s，大小 %d 字节，32 字节记录 %d 条，分组 %d 个。"
                    "v1.0 仅计数，不解码事件，因此本报告不含 AHI、漏气。" % (
                        html.escape(os.path.basename(evt_info["path"])),
                        evt_info["size"], evt_info["records"], evt_info["groups"]))
    last_html = "<p>暂无完整夜晚。</p>"
    if last and prev:
        last_html = ("<table><tr><th></th><th>最新一晚</th><th>上一晚</th></tr>"
                     "<tr><td>开始</td><td>%s</td><td>%s</td></tr>"
                     "<tr><td>时长（小时）</td><td>%.2f</td><td>%.2f</td></tr>"
                     "<tr><td>均压 IPAP / EPAP</td><td>%.2f / %.2f</td><td>%.2f / %.2f</td></tr>"
                     "<tr><td>潮气量均值</td><td>%s</td><td>%s</td></tr>"
                     "<tr><td>呼吸频率均值</td><td>%s</td><td>%s</td></tr></table>" % (
                         html.escape(last["start"]), html.escape(prev["start"]),
                         last["dur_h"], prev["dur_h"],
                         last["ipap_mean"], last["epap_mean"],
                         prev["ipap_mean"], prev["epap_mean"],
                         fmt(last["tidal_mean"], 1), fmt(prev["tidal_mean"], 1),
                         fmt(last["resp_mean"], 2), fmt(prev["resp_mean"], 2)))
    curves_json = json.dumps(curves, ensure_ascii=False)
    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BMC RESmart 完整读取报告</title>
<style>body{font-family:system-ui,-apple-system,PingFang SC,Microsoft YaHei,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;line-height:1.6;color:#222}table{border-collapse:collapse;width:100%%;margin:12px 0}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f0f0f0}.warn{background:#fff8e1;border:1px solid #e6c200;padding:12px;margin:16px 0}canvas{width:100%%;height:320px;border:1px solid #ccc}select,button{font-size:16px;padding:6px}</style>
</head><body>
<h1>BMC RESmart 完整读取报告</h1>
<p>生成器 generate_bmc_report.py %s · 生成时间 %s · 卡根名 %s · 卡路径 %s</p>
<h2>总览</h2>
<table><tr><th>指标</th><th>数值</th></tr>
<tr><td>原始包总数 / 有效包（0xAAAA）</td><td>%d / %d</td></tr>
<tr><td>总记录时长</td><td>%.2f 小时</td></tr>
<tr><td>完整夜晚（≥1 小时）</td><td>%d 夜，共 %.2f 小时</td></tr>
<tr><td>短片段（&lt;1 小时，多为开机起压）</td><td>%d 个，共 %.2f 小时</td></tr>
<tr><td>时间跨度</td><td>%s 至 %s</td></tr>
<tr><td>全部完整夜平均时长 / 均压 / 潮气量 / 呼吸频率</td><td>%.2f 小时 / %.2f cmH2O / %s ml / %s 次/分</td></tr>
</table>
<div class="warn"><b>口径说明（必读）：</b>压力、潮气量、呼吸频率来自公开逆向工程推测的原始包字段，不是 BMC 官方规格；本报告不含 AHI、漏气，%s
本报告仅供个人回顾参考，不用于诊断，不提示调压，调压请问医生。</div>
<h2>最新一晚与上一晚比较</h2>
%s
<h2>按月统计（完整夜）</h2>
<table><tr><th>月份</th><th>夜数</th><th>小时</th><th>均压 cmH2O</th></tr>%s</table>
<h2>每夜总表（完整夜）</h2>
<table><tr><th>#</th><th>开始</th><th>结束</th><th>时长 h</th><th>IPAP 均值</th><th>EPAP 均值</th><th>潮气量 ml</th><th>呼吸频率</th></tr>%s</table>
<h2>每夜曲线（按分钟均值）</h2>
<p>选夜晚：<select id="night"></select> 选指标：<select id="metric">
<option value="1">IPAP</option><option value="2">EPAP</option>
<option value="3">潮气量</option><option value="4">呼吸频率</option></select></p>
<canvas id="cv" width="1000" height="320"></canvas>
<p id="note"></p>
<script>
var CURVES = %s;
var sel = document.getElementById('night');
Object.keys(CURVES).forEach(function(k){
  var o = document.createElement('option'); o.value = k;
  o.text = CURVES[k].start + ' 至 ' + CURVES[k].end; sel.appendChild(o);
});
function draw(){
  var c = CURVES[sel.value]; if(!c) return;
  var mi = parseInt(document.getElementById('metric').value);
  var vals = c.points.map(function(p){return p[mi];}).filter(function(v){return v!==null;});
  var mn = Math.min.apply(null, vals), mx = Math.max.apply(null, vals);
  var cv = document.getElementById('cv'), ctx = cv.getContext('2d');
  ctx.clearRect(0,0,cv.width,cv.height);
  ctx.beginPath();
  c.points.forEach(function(p,i){
    var v = p[mi]; if(v===null) return;
    var x = 40 + (c.points.length>1 ? i/(c.points.length-1)*940 : 0);
    var y = 300 - (mx>mn ? (v-mn)/(mx-mn)*260 : 130);
    if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
  });
  ctx.stroke();
  document.getElementById('note').textContent = '夜晚 ' + c.start + ' 至 ' + c.end + '，共 ' + c.points.length + ' 分钟，指标范围 ' + mn + ' 至 ' + mx;
}
sel.addEventListener('change', draw);
document.getElementById('metric').addEventListener('change', draw);
if(sel.options.length) draw();
</script>
<h2>核对</h2>
<p>原始文件：%s，共 %d 个；有效包占比 %.2f%%。短片段 %d 个，未计入每夜总表。</p>
</body></html>
""" % (VERSION, summary["generated"], html.escape(summary["root"]),
       html.escape(summary["card_path"]),
       summary["total_packets"], summary["valid_packets"],
       summary["total_hours"], len(full), summary["full_hours"],
       len(brief), summary["brief_hours"],
       html.escape(summary["first"]), html.escape(summary["last"]),
       summary["mean_dur"], summary["mean_ipap"],
       fmt(summary["mean_tidal"], 1), fmt(summary["mean_resp"], 2),
       evt_html, last_html, monthly_html, rows_html, curves_json,
       html.escape(", ".join(summary["file_names"])), len(summary["file_names"]),
       (100.0 * summary["valid_packets"] / summary["total_packets"]
        if summary["total_packets"] else 0), len(brief))


def main():
    ap = argparse.ArgumentParser(description="BMC RESmart GII complete reader")
    ap.add_argument("--path", "-p", default=None, help="SD card mount path")
    ap.add_argument("--output-dir", "-o", default=None, help="Output directory")
    args = ap.parse_args()
    card_path = find_card(args.path)
    if not card_path or not os.path.isdir(card_path):
        print("未找到 SD 卡。请插入 BMC 卡，或用 --path 指定挂载点。", file=sys.stderr)
        return 2
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = args.output_dir or os.path.join(script_dir, "output")
    os.makedirs(out_dir, exist_ok=True)
    root, files, minutes, total_packets, valid_packets = parse_card(card_path)
    if not files:
        print("卡上未找到 *.000-*.029 原始文件。", file=sys.stderr)
        return 2
    sessions = build_sessions(minutes)
    full = [s for s in sessions if s["dur_h"] >= 1.0]
    brief = [s for s in sessions if s["dur_h"] < 1.0]
    full_hours = round(sum(s["dur_h"] for s in full), 2)
    brief_hours = round(sum(s["dur_h"] for s in brief), 2)
    summary = {
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "root": root, "card_path": card_path,
        "file_names": [os.path.basename(f) for f in files],
        "total_packets": total_packets, "valid_packets": valid_packets,
        "total_hours": round(valid_packets / 3600.0, 2),
        "full_hours": full_hours, "brief_hours": brief_hours,
        "first": sessions[0]["start"] if sessions else "",
        "last": sessions[-1]["end"] if sessions else "",
        "mean_dur": round(statistics.mean([s["dur_h"] for s in full]), 2) if full else 0,
        "mean_ipap": round(statistics.mean([s["ipap_mean"] for s in full]), 2) if full else 0,
        "mean_tidal": round(statistics.mean([s["tidal_mean"] for s in full if s["tidal_mean"] is not None]), 1) if full else None,
        "mean_resp": round(statistics.mean([s["resp_mean"] for s in full if s["resp_mean"] is not None]), 2) if full else None,
    }
    evt_info = count_evt(card_path, root)
    monthly = monthly_table(full)
    html_text = build_html(summary, full, brief, monthly, minutes, evt_info)
    with open(os.path.join(out_dir, "bmc_report.html"), "w", encoding="utf-8") as fh:
        fh.write(html_text)
    with open(os.path.join(out_dir, "nights.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["start", "end", "duration_h", "span_h", "ipap_mean", "epap_mean", "tidal_mean", "resp_mean"])
        for s in full:
            w.writerow([s["start"], s["end"], s["dur_h"], s["span_h"],
                        s["ipap_mean"], s["epap_mean"], s["tidal_mean"], s["resp_mean"]])
    with open(os.path.join(out_dir, "all_sessions.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["start", "end", "duration_h", "span_h", "ipap_mean", "epap_mean", "tidal_mean", "resp_mean", "full_night"])
        for s in sessions:
            w.writerow([s["start"], s["end"], s["dur_h"], s["span_h"],
                        s["ipap_mean"], s["epap_mean"], s["tidal_mean"], s["resp_mean"],
                        "yes" if s["dur_h"] >= 1.0 else "no"])
    print("卡：%s，根名：%s，原始文件 %d 个" % (card_path, root, len(files)))
    print("有效包 %d / %d，总时长 %.2f 小时" % (valid_packets, total_packets, summary["total_hours"]))
    print("完整夜 %d 夜 %.2f 小时，短片段 %d 个 %.2f 小时" % (len(full), full_hours, len(brief), brief_hours))
    print("时间跨度 %s 至 %s" % (summary["first"], summary["last"]))
    if evt_info:
        print(".evt：%d 条 32 字节记录，分组 %d 个（v1.0 仅计数，不解码事件）" % (evt_info["records"], evt_info["groups"]))
    print("报告：%s" % os.path.join(out_dir, "bmc_report.html"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
