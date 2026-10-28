#!/usr/bin/env bash
# piigate hook (SessionStart): ~/.local/bin/piigate → bin/piigate of the current plugin version. The plugin directory in
# the cache contains a version hash and changes on install and update, while a human needs `piigate` in a normal shell
# (piigate project approve, reversing pseudonyms). Only a symlink is (re)created: a regular file or directory at
# ~/.local/bin/piigate is never overwritten, and no other name in ~/.local/bin is touched. Errors do not interrupt the
# session. Only for an installed copy (…/plugins/cache/…): a development checkout loaded with --plugin-dir (tests,
# e2e) must not repoint the user's command.
set -uo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $root == */plugins/cache/* ]] || exit 0
target="$root/bin/piigate"
link="$HOME/.local/bin/piigate"
[[ -x $target && -d $HOME/.local/bin ]] || exit 0
[[ -e $link && ! -L $link ]] && exit 0
[[ $(readlink "$link" 2>/dev/null) == "$target" ]] || ln -sfn "$target" "$link" 2>/dev/null
exit 0
