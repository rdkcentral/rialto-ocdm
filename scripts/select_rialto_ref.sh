#!/bin/sh
#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2026 Sky UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
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
