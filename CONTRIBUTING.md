# Contributing

Bypass reports, new cases and fixes are all welcome. The bar is the one the repository already holds
itself to: a real mechanism, tests that fire, and honest documented limits.

## Before you open a pull request

```bash
./tests/run-all.sh
```

It must end in `ALL CHECKS PASSED`, and CI runs the same command on every pull request.

## Rules for a change

1. **Every rule ships with both halves.** A case the hook must refuse, and the harmless twin it must
   allow. A fix that only proves the refusing direction is how a new over-block ships. The
   `guard-git` and `guard-find` matrices are the pattern to copy.
2. **A bypass becomes a battery case before it becomes a fix.** Add the failing case, watch it fail,
   then change the hook.
3. **A wrong ALLOW is never an acceptable trade** for fewer prompts. When a command is ambiguous, the
   answer is ASK.
4. **Standard library only** for the Python hooks. `guard-find.sh` needs `jq` and nothing else.
5. **No identifiers.** No hostnames, internal IPs, usernames or home paths. The leak sweep at the end of
   the suite fails the build on your own username and home directory, so run it on your machine.
6. **Update the Known limitations table** when a change opens or closes a documented shape. That table
   is part of the product.

## Commit messages

Describe the failure the change closes, not the file you touched. "Close the quoted-flag bypass" tells
the next reader what was wrong; "update guard-find.sh" does not.
