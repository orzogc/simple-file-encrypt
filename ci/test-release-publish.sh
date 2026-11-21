#!/usr/bin/env bash
# Tests the publishing gate of .github/workflows/release.yml: the script
# that decides which downloaded archives reach a GitHub release. That
# workflow only runs for tags, so CI runs the script's exact text here,
# against fixtures and with a stub in place of gh: genuine archives must
# be published, and anything else must stop the release.
set -euo pipefail

cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

# The `run` block of the publishing step: the lines indented deeper than
# its `run: |`, up to the end of the block. Lines of spaces only belong
# to the block as empty lines, as YAML reads them.
awk '
  /^      - name: Publish to GitHub Releases$/ { step = 1; next }
  step && /^        run: \|$/ { body = 1; next }
  body && /^          / { print substr($0, 11); next }
  body && /^ *$/ { print ""; next }
  body { exit }
' .github/workflows/release.yml > "${work}/publish.sh"
if ! grep -q 'gh release create' "${work}/publish.sh"; then
  echo "could not extract the publishing script from release.yml" >&2
  exit 1
fi

# Stand-in for gh: records its arguments, one per line.
mkdir "${work}/bin"
printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$@" > "${GH_CALL}"' > "${work}/bin/gh"
chmod +x "${work}/bin/gh"

tag=v9.9.9
targets=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl aarch64-apple-darwin)
# Digests the build legs "reported", as the JSON the workflow passes in;
# rebuilt for every scenario and open to its tampering.
digests='{}'
failures=0

# Prints the archive name of target $1.
archive() {
  echo "simple-file-encrypt-${tag}-$1.tar.gz"
}

# Succeeds if the gh call recorded in $1 publishes exactly the archives
# and checksum files of the targets named after it, and each checksum
# file is the line `sha256sum` prints for its archive.
published() {
  local call=$1 dir want target name digest
  dir=$(dirname "${call}")
  shift
  [ -f "${call}" ] || return 1
  [ "$(head -n 5 "${call}" | tr '\n' ' ')" = "release create ${tag} --verify-tag --generate-notes " ] || return 1
  want=$(for target in "$@"; do
    echo "dist/$(archive "${target}")"
    echo "checksums/$(archive "${target}").sha256"
  done | sort)
  [ "$(tail -n +6 "${call}" | sort)" = "${want}" ] || return 1
  for target in "$@"; do
    name=$(archive "${target}")
    digest=$(jq -r --arg target "${target}" '.[$target]' <<<"${digests}")
    printf '%s  %s\n' "${digest}" "${name}" | cmp -s - "${dir}/checksums/${name}.sha256" || return 1
    (cd "${dir}/dist" && sha256sum -c "../checksums/${name}.sha256") > /dev/null || return 1
  done
}

# Runs one scenario, described by $1. Builds dist/ with a genuine
# archive per target and the matching digests, lets the function $3
# tamper with either, runs the publishing script, and checks the outcome
# against $2: "refuse", or "publish" with the targets expected in the
# release as the remaining arguments. A refusal must not call gh, nor
# write through a link planted in dist/ (see planted_link).
scenario() {
  local description=$1 expect=$2 tamper=$3 dir status=0 target file
  shift 3
  dir=$(mktemp -d "${work}/case.XXXXXX")
  mkdir "${dir}/dist"
  digests='{}'
  for target in "${targets[@]}"; do
    file="${dir}/dist/$(archive "${target}")"
    echo "archive for ${target}" > "${file}"
    digests=$(jq --arg target "${target}" \
      --arg digest "$(sha256sum "${file}" | cut -d' ' -f1)" \
      '.[$target] = $digest' <<<"${digests}")
  done
  "${tamper}" "${dir}/dist"

  (cd "${dir}" && PATH="${work}/bin:${PATH}" GH_CALL="${dir}/gh-call" \
    GITHUB_REF_NAME="${tag}" DIGESTS="${digests}" \
    bash -e "${work}/publish.sh") > "${dir}/log" 2>&1 || status=$?

  if [ "${expect}" = publish ]; then
    if [ "${status}" -eq 0 ] && published "${dir}/gh-call" "$@"; then
      echo "ok    published: ${description}"
      return
    fi
  elif [ "${status}" -ne 0 ] && [ ! -e "${dir}/gh-call" ] && [ ! -e "${dir}/outside" ]; then
    echo "ok    refused:   ${description}"
    return
  fi
  echo "FAIL  expected to ${expect}: ${description} (exit status ${status})"
  sed 's/^/        /' "${dir}/log"
  failures=$((failures + 1))
}

# Tampering functions; each gets the dist/ directory.

untouched() {
  :
}

# A target removed from the build matrix: neither built nor reported.
dropped_target() {
  digests=$(jq --arg target "${targets[2]}" 'del(.[$target])' <<<"${digests}")
  rm "$1/$(archive "${targets[2]}")"
}

changed_archive() {
  echo "appended" >> "$1/$(archive "${targets[0]}")"
}

swapped_archives() {
  mv "$1/$(archive "${targets[0]}")" "$1/held"
  mv "$1/$(archive "${targets[1]}")" "$1/$(archive "${targets[0]}")"
  mv "$1/held" "$1/$(archive "${targets[1]}")"
}

missing_archive() {
  rm "$1/$(archive "${targets[2]}")"
}

extra_archive() {
  echo "not built here" > "$1/simple-file-encrypt-${tag}-extra.tar.gz"
}

unreported_archive() {
  digests=$(jq --arg target "${targets[1]}" 'del(.[$target])' <<<"${digests}")
}

planted_checksum() {
  echo "planted" > "$1/$(archive "${targets[0]}").sha256"
}

# A link, where a checksum file written next to its archive would land,
# to a file outside dist/.
planted_link() {
  ln -s ../outside "$1/$(archive "${targets[0]}").sha256"
}

hidden_file() {
  echo "hidden" > "$1/.hidden"
}

subdirectory() {
  mkdir "$1/nested"
}

malformed_digest() {
  digests=$(jq --arg target "${targets[0]}" '.[$target] = "deadbeef"' <<<"${digests}")
}

no_digests() {
  digests='{}'
}

nothing_at_all() {
  digests='{}'
  rm "$1"/*
}

scenario "the archives the build legs produced" publish untouched "${targets[@]}"
scenario "fewer targets, built and reported consistently" publish dropped_target "${targets[0]}" "${targets[1]}"
scenario "an archive with changed content" refuse changed_archive
scenario "two archives swapped" refuse swapped_archives
scenario "a missing archive" refuse missing_archive
scenario "an archive under a name no build leg uses" refuse extra_archive
scenario "an archive whose digest was not reported" refuse unreported_archive
scenario "a checksum file among the artifacts" refuse planted_checksum
scenario "a link where a checksum file would go" refuse planted_link
scenario "a hidden file next to the archives" refuse hidden_file
scenario "a directory next to the archives" refuse subdirectory
scenario "a digest that is not a SHA-256" refuse malformed_digest
scenario "archives without any reported digest" refuse no_digests
scenario "no archives and no digests" refuse nothing_at_all

if [ "${failures}" -ne 0 ]; then
  echo "${failures} scenario(s) failed" >&2
  exit 1
fi
