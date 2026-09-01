#!/usr/bin/env sh

source_identity_hash_file() {
  file=$1
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file"
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file"
    return
  fi
  return 1
}

source_identity_hash_stdin() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
    return
  fi
  return 1
}

source_identity_file_list() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 1
  git ls-files --cached --others --exclude-standard |
    LC_ALL=C sort
}

source_tree_build_id() {
  files_tmp=$(mktemp "${TMPDIR:-/tmp}/sponzey-source-files.XXXXXX") || return 1
  manifest_tmp=$(mktemp "${TMPDIR:-/tmp}/sponzey-source-manifest.XXXXXX") || {
    rm -f "$files_tmp"
    return 1
  }

  source_identity_file_list > "$files_tmp" || {
    rm -f "$files_tmp" "$manifest_tmp"
    return 1
  }
  if [ ! -s "$files_tmp" ]; then
    rm -f "$files_tmp" "$manifest_tmp"
    return 1
  fi

  : > "$manifest_tmp"
  while IFS= read -r source_path; do
    if [ -f "$source_path" ]; then
      digest=$(source_identity_hash_file "$source_path" | awk '{ print $1 }') || {
        rm -f "$files_tmp" "$manifest_tmp"
        return 1
      }
      if [ -z "$digest" ]; then
        rm -f "$files_tmp" "$manifest_tmp"
        return 1
      fi
      printf '%s  %s\n' "$digest" "$source_path" >> "$manifest_tmp"
    fi
  done < "$files_tmp"

  if [ ! -s "$manifest_tmp" ]; then
    rm -f "$files_tmp" "$manifest_tmp"
    return 1
  fi

  digest=$(source_identity_hash_stdin < "$manifest_tmp" | awk '{ print $1 }') || {
    rm -f "$files_tmp" "$manifest_tmp"
    return 1
  }
  rm -f "$files_tmp" "$manifest_tmp"

  if [ -z "$digest" ]; then
    return 1
  fi
  printf 'source-tree-sha256:%s' "$digest"
}
