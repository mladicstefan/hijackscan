#!/usr/bin/env python3
"""PreToolUse hook: Claude never pushes, and every commit waits for the user.

Reads the hook JSON on stdin and prints a permission decision:
  deny  - push, push-equivalents, --no-verify, AI attribution trailers,
          tampering with git hooks or Claude settings
  ask   - commit (with the staged diffstat in the prompt), history rewrites,
          destructive working-tree commands, git config writes
  (none) - everything else falls through to the normal permission system

Exit code 0 with JSON on stdout; on internal error it denies (fail closed).
"""
import json
import os
import re
import shlex
import subprocess
import sys

ATTRIBUTION = re.compile(
    r"co-authored-by:|generated with \[?claude|claude-session:|noreply@anthropic\.com",
    re.I,
)
PROTECTED = re.compile(r"\.git/hooks|core\.hookspath|\.claude/(settings[^/\s]*\.json|hooks)", re.I)
WRITE_VERBS = {"rm", "mv", "cp", "ln", "chmod", "chown", "tee", "truncate", "install",
               "dd", "unlink", "rsync"}
IN_PLACE = re.compile(r"\b(sed|perl)\s+(-\w*\s+)*-\w*i")
SEPARATORS = {"&&", "||", ";", "|", "|&", "&", "(", ")", "\n", "!", "{", "}"}
WRAPPERS = {"sudo", "env", "command", "builtin", "nice", "nohup", "time", "timeout",
            "stdbuf", "xargs", "exec", "noglob"}
INTERPRETERS = {"python", "node", "perl", "ruby", "php", "deno", "bun", "osascript"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
# git global options that consume the next token
GIT_OPT_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
               "--super-prefix", "--config-env"}
GIT_BUILTINS = set("""add am annotate apply archive bisect blame branch bundle cat-file check-ignore
checkout cherry cherry-pick citool clean clone commit commit-tree config count-objects describe
diff diff-files diff-index diff-tree difftool fetch filter-branch filter-repo for-each-ref
format-patch fsck gc grep gui hash-object help init instaweb interpret-trailers log ls-files
ls-remote ls-tree maintenance merge merge-base mergetool mv notes pull push range-diff read-tree
rebase reflog remote repack replace request-pull reset restore rev-list rev-parse revert rm
send-email shortlog show show-branch show-ref sparse-checkout stash status submodule switch
symbolic-ref tag update-index update-ref var verify-commit verify-tag worktree write-tree
whatchanged""".split())
GITHUB_DENY = re.compile(
    r"__(push_files|create_or_update_file|delete_file|merge_pull_request|create_branch|"
    r"update_pull_request_branch|enable_pr_auto_merge|create_repository|fork_repository)$"
)
GITHUB_ASK = re.compile(r"__(create_pull_request|update_pull_request)$")


class Verdict(Exception):
    def __init__(self, decision, reason):
        self.decision, self.reason = decision, reason


def deny(reason):
    raise Verdict("deny", reason)


def tokens(cmd):
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()\n!{}")
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:  # unbalanced quotes: fall back to a crude split
        return cmd.split()


def segments(toks):
    seg = []
    for t in toks:
        if t in SEPARATORS or set(t) <= set(";&|"):
            if seg:
                yield seg
            seg = []
        else:
            seg.append(t)
    if seg:
        yield seg


def strip_wrappers(seg):
    i = 0
    while i < len(seg):
        t = seg[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):  # VAR=value prefix
            i += 1
        elif os.path.basename(t) in WRAPPERS:
            name = os.path.basename(t)
            i += 1
            while i < len(seg) and seg[i].startswith("-"):  # wrapper flags
                i += 1
            if name == "timeout" and i < len(seg) and re.fullmatch(r"\d+(\.\d+)?[smhd]?", seg[i]):
                i += 1
        else:
            break
    return seg[i:]


class Ask:
    def __init__(self):
        self.reasons = []

    def add(self, reason):
        if reason not in self.reasons:
            self.reasons.append(reason)


def git_cwd(base, opts):
    cwd = base
    for flag, val in opts:
        if flag == "-C":
            cwd = os.path.join(cwd, os.path.expanduser(val))
    return cwd


def staged_summary(cwd):
    try:
        out = subprocess.run(["git", "diff", "--cached", "--stat", "--no-color"], cwd=cwd,
                             capture_output=True, text=True, timeout=5).stdout.strip()
        branch = subprocess.run(["git", "branch", "--show-current"], cwd=cwd,
                                capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return "(could not read staged changes)"
    lines = out.splitlines()
    if len(lines) > 25:
        lines = lines[:24] + [f"... {len(lines) - 25} more files", lines[-1]]
    return f"branch {branch or '?'}\n" + ("\n".join(lines) if lines else "(nothing staged)")


def resolve_alias(sub, cwd):
    try:
        out = subprocess.run(["git", "config", "--get", f"alias.{sub}"], cwd=cwd,
                             capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return None
    return out or None


def check_commit(args, cwd, ask):
    message_parts = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--no-verify",):
            deny("`git commit --no-verify` skips the repository's git hooks. Commit without it.")
        if a in ("--all", "--include") or a.startswith("--all"):
            deny("Stage files explicitly with `git add <paths>` so the review shows exactly what is committed; do not use `git commit -a/--all`.")
        if a == "--amend":
            ask.add("AMENDS the previous commit (rewrites history).")
        if a.startswith("--message=") or a.startswith("--trailer"):
            message_parts.append(a.split("=", 1)[-1])
            if a == "--trailer" and i + 1 < len(args):
                message_parts.append(args[i + 1]); i += 1
        elif a in ("--message", "-m") and i + 1 < len(args):
            message_parts.append(args[i + 1]); i += 1
        elif a in ("--file", "-F") and i + 1 < len(args):
            path = os.path.join(cwd, os.path.expanduser(args[i + 1]))
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    message_parts.append(fh.read())
            except OSError:
                pass
            i += 1
        elif a.startswith("-") and not a.startswith("--") and len(a) > 1:
            letters = a[1:]
            for j, ch in enumerate(letters):
                if ch == "n":
                    deny("`git commit -n` (--no-verify) skips the repository's git hooks. Commit without it.")
                if ch == "a":
                    deny("Stage files explicitly with `git add <paths>`; do not use `git commit -a`.")
                if ch in "mFCct":  # option takes a value: rest of token or next token
                    val = letters[j + 1:]
                    if not val and i + 1 < len(args):
                        val = args[i + 1]; i += 1
                    if ch == "m":
                        message_parts.append(val)
                    elif ch == "F":
                        try:
                            with open(os.path.join(cwd, val), encoding="utf-8", errors="replace") as fh:
                                message_parts.append(fh.read())
                        except OSError:
                            pass
                    break
        i += 1
    msg = "\n".join(message_parts)
    if ATTRIBUTION.search(msg):
        deny("Commit message contains an AI attribution trailer (Co-Authored-By / Generated with Claude / Claude-Session). The user does not want Claude to co-sign commits: remove it and retry.")
    first = msg.strip().splitlines()[0] if msg.strip() else "(message from editor or template)"
    ask.add(f"COMMIT \"{first[:100]}\"\n{staged_summary(cwd)}")


def check_git(seg, base_cwd, ask, depth):
    opts, i = [], 1
    while i < len(seg) and seg[i].startswith("-"):
        flag = seg[i]
        if "=" in flag:
            flag, val = flag.split("=", 1)
            opts.append((flag, val))
        elif flag in GIT_OPT_ARG and i + 1 < len(seg):
            opts.append((flag, seg[i + 1])); i += 1
        else:
            opts.append((flag, ""))
        i += 1
    for flag, val in opts:
        if flag in ("-c", "--config-env") and re.match(r"(?i)(core\.hookspath|alias\.)", val):
            deny("Overriding core.hooksPath or defining aliases via `git -c` is not allowed.")
    if i >= len(seg):
        return
    sub, args = seg[i], seg[i + 1:]
    cwd = git_cwd(base_cwd, opts)
    if sub not in GIT_BUILTINS and depth < 3:
        alias = resolve_alias(sub, cwd)
        if alias:
            body = alias[1:] if alias.startswith("!") else "git " + alias
            scan(body + " " + " ".join(shlex.quote(a) for a in args), base_cwd, ask, depth + 1)
            return
    flags = set(args)
    if sub == "push" or (sub == "send-email"):
        deny("Claude never pushes. Tell the user the exact command to run themselves, e.g. `git push -u origin <branch>`.")
    if sub == "commit":
        check_commit(args, cwd, ask)
    elif sub == "reset" and flags & {"--hard", "--merge", "--keep"}:
        ask.add("git reset " + " ".join(args) + " DISCARDS working-tree changes.")
    elif sub == "clean" and any(a.startswith("-") and "f" in a.lstrip("-") or a == "--force" for a in args):
        ask.add("git clean deletes untracked files.")
    elif sub == "branch" and (flags & {"-D", "--delete"} or "-d" in flags and "--force" in flags):
        ask.add("Deletes a branch.")
    elif sub in ("checkout", "restore") and ("." in args or "--" in args and sub == "checkout") and "--staged" not in flags:
        ask.add(f"git {sub} {' '.join(args)} DISCARDS uncommitted changes.")
    elif sub in ("rebase", "filter-branch", "filter-repo", "replace", "update-ref"):
        ask.add(f"git {sub} rewrites history or refs.")
    elif sub == "reflog" and args[:1] in (["expire"], ["delete"]):
        ask.add("Expires reflog entries (loses recovery points).")
    elif sub == "stash" and args[:1] in (["drop"], ["clear"]):
        ask.add("Drops stashed work.")
    elif sub == "gc" and any(a.startswith("--prune") for a in args):
        ask.add("git gc --prune deletes unreachable objects.")
    elif sub == "tag" and flags & {"-d", "--delete", "-f", "--force"}:
        ask.add("Deletes or moves a tag.")
    elif sub == "config":
        read_only = flags & {"--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin", "get", "list"}
        positional = [a for a in args if not a.startswith("-")]
        if any(re.match(r"(?i)core\.hookspath", a) for a in positional) and not read_only:
            deny("Changing core.hooksPath would disable the push/commit gate.")
        if not read_only and len(positional) >= 2 or flags & {"--unset", "--unset-all", "--add", "--replace-all", "--edit", "-e", "set", "unset"}:
            ask.add("Writes git config: " + " ".join(args))


def scan(cmd, cwd, ask, depth=0):
    if depth > 3:
        return
    if PROTECTED.search(cmd):
        toks = tokens(cmd)
        if re.search(r"(?<![<>&0-9])>{1,2}(?!&)", cmd) or any(os.path.basename(t) in WRITE_VERBS for t in toks) \
                or IN_PLACE.search(cmd):
            deny("Modifying git hooks, core.hooksPath or Claude settings/hooks is reserved for the user.")
    for seg in segments(tokens(cmd)):
        seg = strip_wrappers(seg)
        if not seg:
            continue
        head = os.path.basename(seg[0])
        if head in SHELLS or head == "eval":
            for j, t in enumerate(seg):
                if t in ("-c", "-lc", "-ic") and j + 1 < len(seg):
                    scan(seg[j + 1], cwd, ask, depth + 1)
            if head == "eval":
                scan(" ".join(seg[1:]), cwd, ask, depth + 1)
            continue
        if head == "git":
            check_git(seg, cwd, ask, depth)
        elif head in ("gh", "hub"):
            sub = " ".join(seg[1:3])
            if sub in ("pr merge", "repo sync", "repo fork", "repo create") or seg[1:2] == ["push"]:
                deny(f"`{head} {sub}` writes to the remote; that is reserved for the user.")
            if sub.startswith("pr create") or sub.startswith("release create"):
                ask.add(f"`{head} {sub}` may push the branch and publishes to GitHub.")
            if seg[1:2] == ["api"] and re.search(r"(?i)-X\s*(POST|PUT|PATCH|DELETE)|--method\s+(POST|PUT|PATCH|DELETE)", " ".join(seg)) and "git/" in " ".join(seg):
                deny("Writing git refs/objects through the GitHub API is reserved for the user.")
        # git run by another program: `find -exec git push`, `parallel git push`, ...
        elif "git" in seg[1:]:
            check_git(seg[seg.index("git", 1):], cwd, ask, depth)
        # git inside interpreter code: python -c "os.system('git push')"
        if head.rstrip("0123456789.") in INTERPRETERS:
            code = " ".join(seg[1:])
            if re.search(r"\bgit\b[^\n;&|]*\bpush\b|\bgit\b[^\n;&|]*--no-verify", code):
                deny("Running git push (or --no-verify) from a script is not allowed; only the user pushes.")


def decide(data):
    tool = data.get("tool_name", "")
    inp = data.get("tool_input") or {}
    if tool.startswith("mcp__"):
        if GITHUB_DENY.search(tool):
            deny(f"{tool} writes commits/branches to GitHub; only the user pushes.")
        if GITHUB_ASK.search(tool):
            raise Verdict("ask", f"{tool}: publishes to GitHub.")
        return None
    if tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        if PROTECTED.search(str(inp.get("file_path", ""))):
            deny("Editing git hooks or Claude settings/hooks is reserved for the user.")
        return None
    if tool != "Bash":
        return None
    ask = Ask()
    scan(inp.get("command", ""), data.get("cwd") or os.getcwd(), ask)
    if ask.reasons:
        raise Verdict("ask", "git-review-gate: review before approving\n" + "\n".join(ask.reasons))
    return None


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
        decide(data)
        return 0
    except Verdict as v:
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                      "permissionDecision": v.decision,
                                      "permissionDecisionReason": v.reason}}
        print(json.dumps(out))
        return 0
    except Exception as e:  # fail closed for anything git-related, open otherwise
        if re.search(r"\b(git|gh|hub)\b|mcp__", raw):
            print(f"git-review-gate internal error ({e}); blocking to be safe.", file=sys.stderr)
            return 2
        return 0


if __name__ == "__main__":
    sys.exit(main())
