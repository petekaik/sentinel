#!/usr/bin/env bash
#
# Build the React SPA into app/static/ and commit the result.
#
# The container stays stdlib-only: Node is a DEVELOPMENT dependency, and the
# image ships the committed build (COPY app/). This script is the only thing
# that runs npm, and it is never run on the NAS or in the image.
#
# `npm ci` rather than `npm install`, so the committed package-lock.json is the
# authority. The lockfile is written once by `npm install` in frontend/ and
# committed with the source; a build that resolves new versions is a build that
# can differ from the one whose output is in app/static/.
set -euo pipefail
cd "$(dirname "$0")/../frontend"
npm ci
npm run build
echo "built app/static; commit it"
