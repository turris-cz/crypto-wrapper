#!/bin/sh
# busybox POSIX-like shell script
set -eu

# protect cache files from other users
umask 0077

SCRIPTNAME=${0##*/}

# hash used for cache indexing and integrity checks
HASH_TYPE='sha256'

CRYPTO_WRAPPER_ROOT_PREFIX='/tmp/crypto_wrapper'


# --------------------------------------------------------------------
stderr_mesage() {
    echo "$SCRIPTNAME: $1: $2" >&2
}


error() {
    stderr_mesage 'error' "$*"
}


warning() {
    stderr_mesage 'warning' "$*"
}

debug() {
    # double negative due to `set -o errexit`
    [ "${DEBUG:-false}" != true ] || stderr_mesage 'debug' "$*"
}


# --------------------------------------------------------------------
hash_file() {
    openssl "$HASH_TYPE" "$file" | awk '{print $2}'
}


hash_string() {
    printf '%s' "$1" | openssl "$HASH_TYPE" | awk '{print $2}'
}


# this function must be called before running any other cache related function
cache_init() {
    local user
    user=$(id -nu)

    # global variable
    CRYPTO_WRAPPER_ROOT="${CRYPTO_WRAPPER_ROOT_PREFIX}_${user}"

    mkdir -p "$CRYPTO_WRAPPER_ROOT"
}


cache_destroy() {
    rm -f "$CRYPTO_WRAPPER_ROOT"/key_*
    rm -f "$CRYPTO_WRAPPER_ROOT"/hash_*
    [ -d "$CRYPTO_WRAPPER_ROOT" ] && rmdir "$CRYPTO_WRAPPER_ROOT"
    return 0
}


# key should be sha256 hash (HASH_TYPE)
cache_set() {
    local key="$1"
    local value="$2"
    local hash=$(hash_string "$value")

    # key is read first so hash must be written before the key
    echo "$value" > "$CRYPTO_WRAPPER_ROOT/hash_$hash"
    echo "$value" > "$CRYPTO_WRAPPER_ROOT/key_$key"
}


# store value $2 for the key reffered in file $1 to cache
cache_set_file() {
    local key
    key=$(hash_file "$1")
    cache_set "$key" "$2"
}


# store value $2 for the key reffered in $1 (any string) to cache
cache_set_string() {
    local key
    key=$(hash_string "$1")
    cache_set "$key" "$2"
}


# key should be sha256 hash (HASH_TYPE)
cache_get() {
    local key="$1"
    local key_file
    local hash
    local hash_file
    local value

    local key_file="$CRYPTO_WRAPPER_ROOT/key_$key"
    [ -f "$key_file" ] || {
        debug "Key was not found in cache"
        return 1
    }
    value=$(cat "$key_file")

    hash=$(hash_string "$value")
    hash_file="$CRYPTO_WRAPPER_ROOT/hash_$hash"
    [ -f "$hash_file" ] || {
        debug "Control file was not found"
        return 2
    }

    [ "$value" = "$(cat "$hash_file")" ] || {
        debug "Control hash does not match the value"
        return 3
    }

    echo "$value"
}


# get value from cache for the key reffered in file $1
cache_get_file() {
    local file="$1"
    local key=$(hash_file "$file")
    local value

    value=$(cache_get "$key") || {
        debug "Value for file '$file' was not found in cache"
        return 1
    }
    echo "$value"
}


# get value from cache for the key reffered in $1 string
cache_get_string() {
    local string="$1"
    local key=$(hash_string "$string")
    local value

    value=$(cache_get "$key") || {
        debug "Value for string '$string' was not found in cache"
        return 1
    }
    echo "$value"
}
