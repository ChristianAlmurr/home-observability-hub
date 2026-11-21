"""integrity: Home Observability Hub's own code, its launchd job and the Claude Code hooks.

A working tree that is simply dirty is `info`: that is development. What is `high` is a change,
between two scans and without a commit, to one of the three things that hold the trust model up:
the gate that confines the fix agent, the launchd job that starts this server, and the hooks
Claude Code runs on every tool call.
"""
import json
import os

from . import util as U

GIT = ["/usr/bin/git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
CRITICAL = ("server.py", "actions.py", "agent_runner.py", "collectors.py", "router.py", "bin/agent_gate.py", "bin/probe.py", "agent/prompt.md")
GATE = "bin/agent_gate.py"
# The hub's own launchd job, as install.sh writes it: ~/Library/LaunchAgents/<label>.plist, label HOH_LABEL or
# com.home-observability-hub.server. Compared with deploy/<JOB> only when the repository has such a file.
JOB = (os.environ.get("HOH_LABEL") or "com.home-observability-hub.server") + ".plist"


def is_critical(rel):
    return rel in CRITICAL or rel.startswith("sentinel/")


def scan(ctx):
    res = U.Result()
    cfg, b = ctx.cfg, ctx.baseline
    first = b.begin("integrity")
    repo = cfg.repo
    rc, out, err = cfg.run(GIT + ["-C", repo, "status", "--porcelain", "--untracked-files=all"], timeout=30)
    rc2, files, _ = cfg.run(GIT + ["-C", repo, "ls-files"], timeout=30)
    dirty = None
    if rc != 0 or rc2 != 0:
        res.unchecked("Home Observability Hub's code against git", "git gave no answer in %s" % cfg.show(repo), keep="repo:")
    else:
        res.items += len(files.splitlines())
        dirty = {}
        for line in out.splitlines():
            if len(line) > 3:
                path = line[3:].split(" -> ")[-1].strip().strip('"')
                dirty[path] = line[:2].strip() or "M"
        if dirty:
            crit = sorted(p for p in dirty if is_critical(p))
            text = "%d file%s in Home Observability Hub's folder differ%s from the last commit%s. While the app is being worked on that is expected; once it is finished, commit, so that a later change stands out." % (
                len(dirty), "" if len(dirty) == 1 else "s", "s" if len(dirty) == 1 else "",
                (", %d of them part of the server or of Sentinel" % len(crit)) if crit else "")
            res.add(U.make_finding("repo:dirty", "integrity", "Home Observability Hub has uncommitted changes", text,
                                   {"type": "file", "name": "home-observability-hub", "path": repo},
                                   [U.Reason("uncommitted", text, "info", 100, measured=True)],
                                   evidence=[("changed", "%s %s" % (dirty[p], p), "git status") for p in (crit + sorted(p for p in dirty if p not in crit))[:20]],
                                   fix={"text": "Review the changes and commit them.", "command": "git -C %s status" % repo},
                                   fp=U.digest(*sorted(dirty)), baseline=first))

    def watch(key, cur, title, why, subject, evidence, fix, committed):
        """`cur` is the current hash. A change that came through a commit is taken into the baseline silently."""
        res.seen.add(key)
        res.items += 1
        old = b.get(key)
        status = b.status(key, cur, "integrity")
        if status != "changed":
            return
        if committed:
            b.accept(key, cur)
            return
        res.add(U.make_finding(key, "integrity", title, why, subject, [U.Reason("changed-outside-git", why, "high", 100, measured=True)],
                               evidence=evidence + [("hash before", (old or "")[:16], "baseline"), ("hash now", (cur or "")[:16], "sha256")],
                               fix=fix, fp=cur, baseline=False))

    gate = os.path.join(repo, GATE)
    h = U.sha256_file(gate)
    if h is None:
        res.unchecked("the agent's gate (bin/agent_gate.py)", "the file could not be read", keep="gate")
    elif dirty is None:
        res.keep.append("gate")
    else:
        watch("gate", h, "The agent's gate changed without a commit",
              "bin/agent_gate.py is what confines the fix agent to its read-only commands. It changed since the last scan and the change is not in git: "
              "if you did not edit it, something else did, and the agent may no longer be confined.",
              {"type": "file", "name": GATE, "path": gate}, [("file", GATE, "Home Observability Hub")],
              {"text": "See what changed. Restore it if the change is not yours.", "command": "git -C %s diff -- %s" % (repo, GATE)},
              committed=GATE not in dirty)
    job = cfg.h("Library", "LaunchAgents", JOB)
    h = U.sha256_file(job)
    if h is not None:
        watch("job", h, "Home Observability Hub's launchd job changed",
              "The file that tells macOS how to start Home Observability Hub changed since the last scan. It decides which program runs, with which settings, every time this Mac starts.",
              {"type": "launch-item", "name": JOB[:-6], "path": job}, [("file", cfg.show(job), "LaunchAgents")],
              {"text": "Compare it with the copy in the repository. If you reinstalled it yourself, mark this trusted.",
               "command": "diff %s %s" % (os.path.join(repo, "deploy", JOB), job)}, committed=False)
        ref = U.sha256_file(os.path.join(repo, "deploy", JOB))
        if ref and ref != h:
            text = "The installed launchd job is not the same as deploy/%s in the repository. One of the two was edited without the other." % JOB
            res.add(U.make_finding("job-differs", "integrity", "The installed launchd job differs from the repository's copy", text,
                                   {"type": "launch-item", "name": JOB[:-6], "path": job}, [U.Reason("job-differs", text, "low", 100, measured=True)],
                                   evidence=[("installed", cfg.show(job), "sha256 " + h[:16]), ("repository", "deploy/" + JOB, "sha256 " + ref[:16])],
                                   fix={"text": "Look at the difference and bring them back in line.", "command": "diff %s %s" % (os.path.join(repo, "deploy", JOB), job)},
                                   fp=U.digest(h, ref), baseline=first))
    else:
        res.unchecked("Home Observability Hub's launchd job", "it is not installed in ~/Library/LaunchAgents", keep="job")
    settings = cfg.h(".claude", "settings.json")
    if U.lstat(settings) is not None:
        try:
            with U.open_nofollow(settings) as f:
                doc = json.loads(f.read(4 * 1024 * 1024).decode("utf-8", "replace"))
            hooks = doc.get("hooks") if isinstance(doc, dict) else None
            h = U.digest(json.dumps(hooks, sort_keys=True))
        except (OSError, ValueError):
            h = None
        if h is None:
            res.unchecked("Claude Code hooks (~/.claude/settings.json)", "the file could not be read as JSON", keep="hooks")
        else:
            watch("hooks", h, "The Claude Code hooks changed",
                  "The hooks in ~/.claude/settings.json changed since the last scan. A hook is a command that runs with your rights on every tool call of every "
                  "Claude Code session on this Mac, so a hook nobody chose is code nobody chose.",
                  {"type": "setting", "name": "Claude Code hooks", "path": settings},
                  [("file", cfg.show(settings), "the hooks section only"), ("hooks now", "%d event(s)" % (len(hooks) if isinstance(hooks, dict) else 0), "settings.json")],
                  {"text": "Open the file and read the hooks section. The Plugins scanner lists each hook and what it runs. If the change is yours, mark this trusted."},
                  committed=False)
    res.detail = "%d tracked files, the agent's gate, the launchd job and the hooks" % res.items
    return res
