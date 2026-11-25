#!/usr/bin/env bash
# stage-native.sh <natives-dir>: copies the per-platform native/<os>-<arch>/ trees from <natives-dir> into the checkout's native/ and
# commits them (git add -f: they are build products, never in source control) as a release-only commit on top of the checked-out tag.
# Composer builds a version's dist from the tag's tree, so the tag has to point at this commit.
set -euo pipefail
SRC="${1:?natives dir}"
mkdir -p native
cp -R "$SRC"/. native/
git add -f native
git -c user.name="github-actions[bot]" -c user.email="41898283+github-actions[bot]@users.noreply.github.com" commit -q -m "release: prebuilt native libraries for ${GITHUB_REF_NAME:-this tag}"
git rev-parse HEAD
