#!/usr/bin/env python3
# BMC RESmart three-way analysis: card raw data + OSCAR database + Clarity reference.
# BMC RESmart 三方对照分析：卡上原始数据 + OSCAR 数据库 + Clarity 参考表。
#
# READ ONLY, 只读：never writes to the card, never writes to the OSCAR database.
# The OSCAR database is copied to a temporary directory first, then queried there,
# so a running OSCAR instance is not disturbed. .usr personal content is never read.
# OSCAR 数据库先拷到临时目录再查，正在运行的 OSCAR 不受影响。.usr 个人内容不读。
#
# What this script does NOT do, 本脚本不做的事：
#   - It does NOT compute an official AHI. It prints the three AHI values side by
#     side, with their own denominators, so the reader can see why they differ.
#     不直接输出官方 AHI，只把三家的 AHI 和分母并排打印，让差异可见。
#   - It does NOT compute leak. There is no validated leak field on the card.
#     不算漏气，卡上没有已验证的漏气字段。
#   - It does NOT map raw .evt groups to Clarity nights by calendar date.
#     Raw groups are matched to Clarity nights by ORDER for the last 13 nights only,
#     because that sequential mapping was verified; date matching is known to be
#     off by about one day. 不按日历日期硬对 raw 组，只对最后 13 夜做顺序对照。
#
# Usage, 用法（在 Mac 上，卡副本、OSCAR 数据库、Clarity 参考表都在本机时）：
#   python3 bmc_three_way_analysis.py \
#       --card "/Users/kenya/Documents/m1dsh/BMC-RESmart/card-copy" \
#       --oscar-db "/Users/kenya/Documents/OSCAR20_Data/oscar.db" \
#       --clarity-csv clarity_reference.csv \
#       --outdir output_three_way
#
# Outputs, 产出：
#   comparison.csv   Clarity date x OSCAR daily, with event and hour differences.
#   raw_groups.csv   Every .idx group with its .evt type distribution and sum123.
#   sequential_13.csv  Last 13 .idx groups in order x Clarity 2023-08-13..25 in order.
#   summary.txt      Totals for all three sources, in plain text.
import os, sys, glob, struct, json, csv, argparse, sqlite3, shutil, tempfile
from collections import Counter, defaultdict
from datetime import datetime

def find_card(explicit):
    if explicit:
        return explicit
    for vol in sorted(glob.glob("/Volumes/*")):
        if glob.glob(os.path.join(vol, "*. [0-9][0-9][0-9]".replace(" ", ""))):
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
        r = data[off:off + 512]
        if r[0:2] != b"\xaa\xaa":
            break
        idx = struct.unpack("<H", r[2:4])[0]
        y = 2000 + r[4]; m = r[5]; d = r[6]
        hh = r[8]; mm = r[9]; ss = r[10]
        try:
            datestr = datetime(y, m, d, hh, mm, ss).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            datestr = "%04d-%02d-%02d %02d:%02d:%02d" % (y, m, d, hh, mm, ss)
        recs.append({"n": idx, "date": datestr})
    return recs, files[0]

def read_evt(card):
    files = glob.glob(os.path.join(card, "*.evt"))
    if not files:
        return {}, 0, None
    data = open(files[0], "rb").read()
    groups = defaultdict(list)
    total = 0
    for off in range(2048, len(data) - 31, 32):
        r = data[off:off + 32]
        if r[0:2] != b"\xaa\xaa":
            continue
        total += 1
        g = struct.unpack("<H", r[2:4])[0]
        t = struct.unpack("<H", r[4:6])[0]
        groups[g].append(t)
    summary = {}
    for g, lst in groups.items():
        cnt = Counter(lst)
        summary[g] = {
            "n": len(lst),
            "types": dict(sorted(cnt.items())),
            "sum123": sum(cnt[t] for t in (1, 2, 3) if t in cnt),
            "small_123_11": sum(cnt[t] for t in (1, 2, 3, 11) if t in cnt),
        }
    return summary, total, files[0]

def read_raw_sessions(card):
    files = sorted(glob.glob(os.path.join(card, "*.[0-9][0-9][0-9]")))
    packets = []
    for fn in files:
        data = open(fn, "rb").read()
        for i in range(len(data) // 256):
            pkt = data[i * 256:(i + 1) * 256]
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
        out.append({"start": start.isoformat(), "end": end.isoformat(),
                    "dur_h": round(dur_h, 2), "packets": len(s),
                    "packet_h": round(len(s) / 3600.0, 2),
                    "ipap": round(mean(2) / 2, 2), "epap": round(mean(3) / 2, 2),
                    "tidal": round(mean(99), 1), "rr": round(mean(104), 1)})
    full = [x for x in out if x["dur_h"] >= 1.0]
    return {"files": len(files), "packets": len(packets), "sessions": out, "full": full}

def read_oscar_daily(oscar_db_path):
    # Copy first, query the copy. 先拷副本再查，原库不动。
    tmpdir = tempfile.mkdtemp(prefix="oscar_check_")
    db_copy = os.path.join(tmpdir, "oscar.db")
    shutil.copyfile(oscar_db_path, db_copy)
    for suffix in ("-wal", "-shm"):
        src = oscar_db_path + suffix
        if os.path.exists(src):
            try:
                shutil.copyfile(src, db_copy + suffix)
            except Exception:
                pass
    con = sqlite3.connect(db_copy)
    try:
        rows = con.execute(
            "SELECT date, session_count, total_hours, ahi, "
            "obstructive_count, hypopnea_count, clear_airway_count, rera_count, "
            "pressure_avg, pressure_95th, leak_total_avg, leak_total_95th "
            "FROM daily_summaries ORDER BY date").fetchall()
        agg = con.execute(
            "SELECT COUNT(*), SUM(total_hours), "
            "SUM(obstructive_count), SUM(hypopnea_count), SUM(clear_airway_count), "
            "SUM(COALESCE(rera_count, 0)), SUM(obstructive_count+hypopnea_count+clear_airway_count) "
            "FROM daily_summaries").fetchone()
    finally:
        con.close()
    daily = {}
    for r in rows:
        daily[r[0]] = {
            "date": r[0], "session_count": r[1], "total_hours": r[2], "ahi": r[3],
            "oa": r[4], "h": r[5], "ca": r[6], "rera": r[7],
            "press_avg": r[8], "press_95th": r[9],
            "leak_avg": r[10], "leak_95th": r[11],
        }
    return daily, agg, tmpdir

def read_clarity_csv(path):
    rows = []
    if path and os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                rows.append(row)
    return rows

def fnum(x, default=""):
    try:
        return float(x)
    except Exception:
        return default

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--card", default=None)
    ap.add_argument("--oscar-db", default=None)
    ap.add_argument("--clarity-csv", default=None)
    ap.add_argument("--outdir", default=None)
    args = ap.parse_args()
    card = find_card(args.card)
    if not card:
        print("Card not found. Use --card /path/to/card-copy.")
        return 2
    script_dir = os.path.dirname(os.path.abspath(__file__))
    outdir = args.outdir or os.path.join(script_dir, "output_three_way")
    os.makedirs(outdir, exist_ok=True)
    print("Card:", card)
    idx, idx_file = read_idx(card)
    print("IDX records:", len(idx), idx_file)
    evt, evt_total, evt_file = read_evt(card)
    print("EVT records:", evt_total, evt_file, "groups:", len(evt))
    raw = read_raw_sessions(card)
    print("Raw files:", raw["files"], "packets:", raw["packets"],
          "sessions:", len(raw["sessions"]), "full nights:", len(raw["full"]))
    # Raw groups table, in idx order.
    raw_rows = []
    for rec in idx:
        e = evt.get(rec["n"], {"n": 0, "types": {}, "sum123": 0, "small_123_11": 0})
        raw_rows.append({"idx": rec["n"], "date": rec["date"], "evt_n": e["n"],
                         "evt_types": json.dumps(e["types"], ensure_ascii=False),
                         "sum123": e["sum123"], "small_123_11": e["small_123_11"]})
    with open(os.path.join(outdir, "raw_groups.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["idx", "date", "evt_n", "evt_types", "sum123", "small_123_11"])
        w.writeheader()
        for r in raw_rows:
            w.writerow(r)
    # OSCAR daily + totals.
    oscar_daily = {}
    oscar_agg = None
    if args.oscar_db and os.path.exists(args.oscar_db):
        oscar_daily, oscar_agg, tmpdir = read_oscar_daily(args.oscar_db)
        print("OSCAR daily rows:", len(oscar_daily), "tmp copy:", tmpdir)
        print("OSCAR totals (days, hours, oa, h, ca, rera, total_events):", oscar_agg)
    else:
        print("OSCAR database not given or not found; comparison will have no OSCAR column.")
    # Clarity reference + comparison by date (Clarity date = OSCAR daily date).
    clarity = read_clarity_csv(args.clarity_csv)
    print("Clarity reference rows:", len(clarity))
    comp_rows = []
    for r in clarity:
        date = r.get("date", "")
        c_oa = int(fnum(r.get("oa"), 0)); c_ca = int(fnum(r.get("ca"), 0)); c_h = int(fnum(r.get("h"), 0))
        c_total = c_oa + c_ca + c_h
        o = oscar_daily.get(date, {})
        o_total = None
        if o:
            o_total = (o["oa"] or 0) + (o["h"] or 0) + (o["ca"] or 0)
        comp_rows.append({
            "date": date, "clarity_ahi": r.get("ahi", ""), "clarity_hours": r.get("hours", ""),
            "clarity_oa": c_oa, "clarity_ca": c_ca, "clarity_h": c_h, "clarity_total": c_total,
            "oscar_ahi": o.get("ahi", ""), "oscar_hours": o.get("total_hours", ""),
            "oscar_oa": o.get("oa", ""), "oscar_ca": o.get("ca", ""), "oscar_h": o.get("h", ""),
            "oscar_total": o_total if o_total is not None else "",
            "diff_total": (o_total - c_total) if o_total is not None else "",
            "tag": r.get("tag", ""),
        })
    with open(os.path.join(outdir, "comparison.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(comp_rows[0].keys()) if comp_rows else [])
        w.writeheader()
        for r in comp_rows:
            w.writerow(r)
    # Sequential mapping for the last 13 nights only, verified by order, not by date.
    # 最后 13 夜顺序对照：卡上最后 13 组按顺序，对 Clarity 2023-08-13..25 按日期升序。
    clarity_13 = sorted([r for r in clarity if "2023-08-13" <= r.get("date", "") <= "2023-08-25"],
                        key=lambda x: x["date"])
    last_13 = raw_rows[-13:] if len(raw_rows) >= 13 else raw_rows
    seq_rows = []
    for raw_r, c_r in zip(last_13, clarity_13):
        c_total = int(fnum(c_r.get("oa"), 0)) + int(fnum(c_r.get("ca"), 0)) + int(fnum(c_r.get("h"), 0))
        seq_rows.append({
            "idx": raw_r["idx"], "idx_date": raw_r["date"], "raw_sum123": raw_r["sum123"],
            "clarity_date": c_r["date"], "clarity_total": c_total,
            "clarity_oa": c_r.get("oa", ""), "clarity_ca": c_r.get("ca", ""),
            "clarity_h": c_r.get("h", ""), "diff_sum123_minus_clarity": raw_r["sum123"] - c_total,
        })
    with open(os.path.join(outdir, "sequential_13.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(seq_rows[0].keys()) if seq_rows else [])
        w.writeheader()
        for r in seq_rows:
            w.writerow(r)
    # Summary, in plain text, with the denominators kept explicit.
    lines = []
    lines.append("BMC RESmart three-way summary")
    lines.append("Card: %s" % card)
    lines.append("IDX groups: %d, EVT records: %d, raw files: %d, raw packets: %d" % (
        len(idx), evt_total, raw["files"], raw["packets"]))
    lines.append("Raw sessions (>=60s): %d, full nights (>=1h): %d" % (
        len(raw["sessions"]), len(raw["full"])))
    if oscar_agg:
        lines.append("OSCAR daily rows: %d, total hours: %.2f, OA: %s, H: %s, CA: %s, RERA: %s, total events: %s" % (
            len(oscar_daily), oscar_agg[1] or 0, oscar_agg[2], oscar_agg[3], oscar_agg[4], oscar_agg[5], oscar_agg[6]))
        if oscar_agg[1]:
            lines.append("OSCAR weighted AHI (total events / total hours): %.3f" % (oscar_agg[6] / oscar_agg[1]))
    if clarity:
        c_tot = sum(int(fnum(r.get("oa"), 0)) + int(fnum(r.get("ca"), 0)) + int(fnum(r.get("h"), 0)) for r in clarity)
        lines.append("Clarity reference rows in CSV: %d, sum of OA+CA+H in those rows: %d (note: this CSV is only a reference subset, not the full 353-night Clarity report)" % (len(clarity), c_tot))
    lines.append("Comparison rows written: %d (by Clarity date = OSCAR daily date)" % len(comp_rows))
    lines.append("Sequential 13 rows written: %d (raw order x Clarity 2023-08-13..25 order; date matching is NOT used here)" % len(seq_rows))
    lines.append("Cautions: AHI values keep their own denominators; leak is not computed from the card; .evt A is a counter, not wall-clock time; .usr personal content is not read.")
    summary = "\n".join(lines) + "\n"
    with open(os.path.join(outdir, "summary.txt"), "w", encoding="utf-8") as f:
        f.write(summary)
    print(summary)
    print("Wrote:", outdir)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
