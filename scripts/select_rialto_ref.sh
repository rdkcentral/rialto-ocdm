#!/bin/sh
set -eu

case "$TARGET_BRANCH" in
    release/v0.10.0)
        # meta-rdk-video support/8.6.3.0, RIALTO_SRCREV
        branch=d7c1221bf9f39615177bc0cbe2cdc44e62156f36
        ;;
    release/v0.9.3)
        # meta-middleware-generic-support support/8.4.4.0, SRCREV:pn-rialto
        branch=ed056254aed65af575aa0f44fdf5a44aed992952
        ;;
    *)
        branch=""
        for candidate in "${PR_HEAD_BRANCH:-}" "$TARGET_BRANCH"; do
            [ -n "$candidate" ] || continue
            if git ls-remote --exit-code --heads https://github.com/rdkcentral/rialto.git "refs/heads/$candidate" > /dev/null; then
                branch="$candidate"
                break
            else
                status=$?
                if [ "$status" -ne 2 ]; then
                    echo "Could not query Rialto branch: $candidate" >&2
                    exit "$status"
                fi
            fi
        done
        if [ -z "$branch" ]; then
            echo "No compatible Rialto ref configured for target: $TARGET_BRANCH" >&2
            exit 1
        fi
        ;;
esac
echo "Using Rialto ref: $branch"
echo "branch=$branch" >> "$GITHUB_OUTPUT"
