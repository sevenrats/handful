#!/bin/bash
cd /workspace/armspan/handful

# 1. Ensure upstream remote
git remote get-url upstream 2>/dev/null || git remote add upstream https://github.com/tailscale/tailscale.git

# 2. Fetch upstream + github tags
git fetch upstream --tags --force
git fetch github --tags --force

# 3. Find handful-specific commits
HANDFUL_BASE=$(git merge-base upstream/main github/main-handful)
echo "Merge base: $HANDFUL_BASE"
git log --oneline "${HANDFUL_BASE}..github/main-handful"

# 4. Create temp branch from upstream v1.94.1
TS_VERSION=v1.94.1
ARMSPAN_TAG=v0.28.0

git branch -D "tmp-handful-${ARMSPAN_TAG}" 2>/dev/null || true
git checkout -b "tmp-handful-${ARMSPAN_TAG}" "refs/tags/${TS_VERSION}"

# 5. Rebase handful commits onto the tailscale release tag
git rebase --onto "tmp-handful-${ARMSPAN_TAG}" "$HANDFUL_BASE" "github/main-handful"

# 6. Tag and push
git tag -f "$ARMSPAN_TAG"
git push --force github "refs/tags/${ARMSPAN_TAG}"

# 7. Cleanup — go back to main-handful
git checkout main-handful
git branch -D "tmp-handful-${ARMSPAN_TAG}" 2>/dev/null || true