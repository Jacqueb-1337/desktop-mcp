"""Repeatable synthetic search benchmark; optional psutil reports worker RSS."""
import argparse
import json
import pathlib
import statistics
import subprocess
import tempfile
import time

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("agent", type=pathlib.Path)
    parser.add_argument("--dirs", type=int, default=100)
    parser.add_argument("--files", type=int, default=100)
    args = parser.parse_args()
    exe = str(args.agent.resolve())
    with tempfile.TemporaryDirectory(prefix="dmcp-search-") as directory:
        root = pathlib.Path(directory)
        subprocess.run(["git", "init", "-q", directory], check=True)
        for i in range(args.dirs):
            folder = root / f"dir{i:04}"
            folder.mkdir()
            for j in range(args.files):
                text = "hello world\n" * 30
                if (i, j) == (args.dirs-1, args.files-1):
                    text += "needle_unique\n"
                (folder / f"source{j:04}.txt").write_text(text)
        query = {"engine":"native","mode":"paths","pattern":f"source{args.files-1:04}.txt","limit":min(args.dirs,200)}
        started = time.perf_counter()
        result = subprocess.run([exe,"--readonly-search-worker","--workspace",directory,json.dumps(query)],
                                capture_output=True,text=True,check=True)
        baseline_ms = (time.perf_counter()-started)*1000
        assert len(json.loads(result.stdout)["data"]["results"]) == min(args.dirs,200)
        session = subprocess.Popen([exe,"--readonly-search-session","--workspace",directory],
                                   stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        def ask(q):
            started = time.perf_counter()
            session.stdin.write(json.dumps(q)+"\n")
            session.stdin.flush()
            result = json.loads(session.stdout.readline())["data"]
            return (time.perf_counter()-started)*1000,result
        try:
            cold, result = ask(query)
            warm = [ask(query) for _ in range(5)]
            assert all(r["results"] == result["results"] for _,r in warm)
            print("files", args.dirs*args.files)
            print("one_shot_ms",round(baseline_ms,2))
            print("cold_ms",round(cold,2))
            print("warm_median_ms",round(statistics.median(t for t,_ in warm),2))
            print("index_hits",sum(r["index_hit"] for _,r in warm))
            try:
                import psutil
                print("worker_rss_mib",round(psutil.Process(session.pid).memory_info().rss/1048576,2))
            except ImportError:
                print("worker_rss_mib unavailable (optional psutil not installed)")
            (root/"newfile.txt").write_text("new")
            time.sleep(.25)
            elapsed, result = ask({"mode":"paths","pattern":"newfile.txt","engine":"native"})
            assert result["results"] == [{"path":"newfile.txt"}], result
            print("invalidation_ms",round(elapsed,2))
            for scope in (None,f"dir{args.dirs-1:04}"):
                q = {"mode":"text","pattern":"needle_unique","engine":"native"}
                if scope: q["scope"] = scope
                elapsed,result = ask(q)
                print("text_ms",round(elapsed,2),"scope",scope,"matches",len(result["results"]),
                      "budget_exhausted",result["scan_budget_exhausted"])
            q={"mode":"text","pattern":"needle_unique","engine":"fff"}
            cold,result=ask(q)
            print("fff_cold_ms",round(cold,2),"ready",result.get("content_index_ready"),"matches",len(result["results"]),"budget_exhausted",result["scan_budget_exhausted"])
            warm,result=ask(q)
            print("fff_warm_ms",round(warm,2),"ready",result.get("content_index_ready"),"matches",len(result["results"]),"prefiltered",result.get("prefiltered_files"),"budget_exhausted",result["scan_budget_exhausted"])
            try:
                import psutil
                print("fff_worker_rss_mib",round(psutil.Process(session.pid).memory_info().rss/1048576,2))
            except ImportError:
                pass
            q={"mode":"paths","pattern":"sorce0099","engine":"fff","limit":1}
            elapsed,result=ask(q)
            print("fff_fuzzy_ms",round(elapsed,2),"result",result["results"][:1])
        finally:
            session.terminate()
            session.wait(timeout=5)

if __name__ == "__main__":
    main()
