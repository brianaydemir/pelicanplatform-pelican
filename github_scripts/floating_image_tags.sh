#!/bin/bash
#
# Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You may
# obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Prints the floating container image tags, one per line, that the release
# tag given as the sole argument should also receive. The candidate tags to
# compare it against are read from stdin; the argument is always included.
#
#   - Before v26: "latest", if the tag is the highest release before v26.
#   - vN.0.z, N >= 26: "vN.0", if the tag is the highest vN.0.z.
#   - vN.y.z, N >= 26, y >= 1: "vN.x", if the tag is the highest such vN.y.z.
#
# Prints nothing for anything other than a vX.Y.Z tag, e.g., a release
# candidate.
#
# Usage: git tag -l | floating_image_tags.sh v26.1.0

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <tag>" >&2
  exit 2
fi

tag=$1
release_re='^v([0-9]+)\.([0-9]+)\.([0-9]+)$'

if ! [[ ${tag} =~ ${release_re} ]]; then
  exit 0
fi
major=$((10#${BASH_REMATCH[1]}))
minor=$((10#${BASH_REMATCH[2]}))

# Print the highest of the release tags on stdin that satisfy the given
# predicate on their major and minor version numbers.
highest () {
  local predicate=$1 t
  while read -r t; do
    if [[ ${t} =~ ${release_re} ]] \
       && "${predicate}" $((10#${BASH_REMATCH[1]})) $((10#${BASH_REMATCH[2]}))
    then
      echo "${t}"
    fi
  done | sort -V | tail -n 1
}

before_26 () { [ "$1" -lt 26 ]; }
same_x_0 () { [ "$1" -eq "${major}" ] && [ "$2" -eq 0 ]; }
same_x_y () { [ "$1" -eq "${major}" ] && [ "$2" -ge 1 ]; }

if [ "${major}" -lt 26 ]; then
  predicate=before_26
  floating=latest
elif [ "${minor}" -eq 0 ]; then
  predicate=same_x_0
  floating="v${major}.0"
else
  predicate=same_x_y
  floating="v${major}.x"
fi

if [ "$({ cat; printf '\n%s\n' "${tag}"; } | highest "${predicate}")" = "${tag}" ]; then
  echo "${floating}"
fi
