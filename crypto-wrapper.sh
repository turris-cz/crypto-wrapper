#!/bin/sh
# busybox POSIX-like shell script
set -eu

# protect cache files from other users
umask 0077

VERSION='0.1-alpha'
SCRIPTNAME=${0##*/}
USAGE="USAGE
    General syntax:
        $SCRIPTNAME command [args..]

        High-level command for Turris devices to query cryptographic functions
        and device info stored during production. This command unifies
        hardware-specific commands such as \`atsha204cmd\` for Turris 1.x and
        Omnia and \`mox-otp\` for MOX.

        All query commands are cached on the filesystem so querying same
        commands will not wear-out cryptographic device.

    Available commands:
        $SCRIPTNAME help
                    Print this message end exits

        $SCRIPTNAME version
                    Print script version and exits

        $SCRIPTNAME serial-number
                    Print serial number of the device

        $SCRIPTNAME sign [file]
                    \"Sign\" given file or standard input if no file is given.
                    Signing on atsha-equipped device is realized via HMAC
                    function with shared secret.

        $SCRIPTNAME sign-hash hash
                    Sign given hash; it must include only hexadecimal characters

                    WARNING:    low-level command; hash must be exactly the one
                                underlying command expects (sha512 on MOX and
                                sha256 on atsha-equipped device)

        $SCRIPTNAME clear-cache
                    Remove all command cache
"

# hash used for cache indexing and integrity checks
HASH_TYPE='sha256'

CRYPTO_WRAPPER_ROOT_PREFIX='/tmp/crypto_wrapper'

SYSINFO_MODEL_FILE='/tmp/sysinfo/model'
TYPE_ATSHA='atsha'
TYPE_OTP='otp'

# length of a hash for given type (number of hexadecimal characters)
HASH_LENGTH_ATSHA='64'
HASH_LENGTH_OTP='128'


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
    rm -f "$CRYPTO_WRAPPER_ROOT"/temp_*
    [ -d "$CRYPTO_WRAPPER_ROOT" ] && rmdir "$CRYPTO_WRAPPER_ROOT"
    return 0
}


# create empty temporary file in cache root
cache_mktemp() {
    mktemp "$CRYPTO_WRAPPER_ROOT/temp_XXXXXX"
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


# --------------------------------------------------------------------
# Run command with output saved to cache. If some value is found in the cache,
# output is get directly from cache without actually running the command.
#
# First argument is the key type ('string' or 'file') second is the key to the
# cache and the rest is command to run
cached_command() {
    local key_type="$1"
    local key="$2"
    local cmd="$3"
    local output cache_get_funtion cache_set_funtion
    # the rest is arguments
    shift 3

    if   [ "$key_type" = 'string' ]; then
        cache_get_funtion=cache_get_string
        cache_set_funtion=cache_set_string
    elif [ "$key_type" = 'file' ]; then
        cache_get_funtion=cache_get_file
        cache_set_funtion=cache_set_file
    else
        error "'cached_command: Undefined cache key type '$key_type'"
        return 4
    fi

    if output=$("$cache_get_funtion" "$key"); then
        debug "key '$key' found in cache"
    else
        debug "key '$key' was not found in cache, run the command"
        output=$("$cmd" "$@") || {
            error "Failed to run command '$cmd $*'"
            return 5
        }

        debug 'store output of the command to cache'
        "$cache_set_funtion" "$key" "$output"
    fi

    echo "$output"
}


cached_atsha_serial() {
    cached_command string 'serial' 'atsha204cmd' 'serial-number'
}


# 64-bytes hex string from stdin
cached_atsha_challenge_response() {
    local hash="$1"

    # read hash from file to avaid unsafe pipe
    local temp=$(cache_mktemp)
    echo "$hash" > "$temp"

    cached_command string "$hash" 'atsha204cmd' 'challenge-response' < "$temp"

    rm "$temp"
}


cached_atsha_challenge_response_file() {
    local file="$1"

    # this is wierd atsha204cmd interface and I need to avoid unsafe pipe in
    # busybox shell
    local filename=$(cache_mktemp)
    echo "$file" > "$filename"

    cached_command file "$file" 'atsha204cmd' 'file-challenge-response' < "$filename"

    rm "$filename"
}


cached_otp_serial() {
    cached_command string 'serial' 'mox-otp' 'serial-number'
}


# 128-bytes hex string from stdin
cached_otp_sign_hash() {
    local hash="$1"
    cached_command string "$hash" 'mox-otp' 'sign-hash' "$hash"
}


cached_otp_sign() {
    local file="$1"
    cached_command file "$file" 'mox-otp' 'sign' "$file"
}


# --------------------------------------------------------------------
get_device_type(){
    local model

    [ -f "$SYSINFO_MODEL_FILE" ] || {
        error "Unknown device model; sysinfo file is missing '$SYSINFO_MODEL_FILE'"
        return 2
    }

    model=$(cat "$SYSINFO_MODEL_FILE")
    case "$model" in
        # WARNING:
        #   Turris string is also included in other models
        #   This case must not include wildcards
        Turris)
            debug "Device recognized as Turris 1.x"
            echo "$TYPE_ATSHA"
            ;;

        *Omnia*)
            debug "Device recognized as Omnia"
            echo "$TYPE_ATSHA"
            ;;

        *Mox*)
            debug "Device recognized as MOX"
            echo "$TYPE_OTP"
            ;;

        *)
            error "Unknown device model: '$model'"
            return 2
            ;;

    esac
}


# --------------------------------------------------------------------
do_serial() {
    local device_type
    cache_init

    device_type=$(get_device_type)
    if   [ "$device_type" = "$TYPE_ATSHA" ]; then
        debug "Call atsha serial-number"
        cached_atsha_serial

    elif [ "$device_type" = "$TYPE_OTP" ]; then
        debug "Call otp serial-number"
        cached_otp_serial

    else
        error "Unsupported device_type '$device_type'"
        return 2
    fi
}


do_sign() {
    local file="$1"
    local tmp=''
    local device_type
    cache_init

    # use stdin if no file is given – store it to temp file
    [ -z "$file" ] && {
        tmp=$(cache_mktemp)
        debug "Store stdin to '$tmp'"
        cat > "$tmp"
        file="$tmp"
    }

    [ -f "$file" -a -r "$file" ] || {
        error "'$file' is not a readable file"
        return 1
    }

    device_type=$(get_device_type)
    case "$device_type" in
        "$TYPE_ATSHA")
            debug "Call atsha file-challenge-response with '$file'"
            cached_atsha_challenge_response_file "$file"
            ;;

        "$TYPE_OTP")
            debug "Call otp sign with '$file'"
            cached_otp_sign "$file"
            ;;

        *)
            error "Unsupported device_type '$device_type'"
            return 2
            ;;

    esac

    # remove temp file if it was used
    [ -z "$tmp" ] || rm -f "$tmp"
}


do_sign_hash() {
    # avoid multiline variable and capital letters
    # busybox does not support neither ${var,,} nor tr [:upper:] [:lower:]
    local hash=$(echo "${1}" | head -n 1 | tr 'A-Z' 'a-z')
    local device_type
    cache_init

    [ -z "$(echo "$hash" | tr -d '0-9a-f')" ] || {
        error 'Given hash is not hexadecimal string'
        return 1
    }

    device_type=$(get_device_type)
    if   [ "$device_type" = "$TYPE_ATSHA" ]; then
        [ "${#hash}" -eq "$HASH_LENGTH_ATSHA" ] || {
            error "Hash for atsha must have $HASH_LENGTH_ATSHA hexadecimal characters"
            return 1
        }

        debug "Call atsha challenge-response with '$hash'"
        cached_atsha_challenge_response "$hash"

    elif [ "$device_type" = "$TYPE_OTP" ]; then
        [ "${#hash}" -eq "$HASH_LENGTH_OTP" ] || {
            error "Hash for atsha must have $HASH_LENGTH_OTP hexadecimal characters"
            return 1
        }

        debug "Call otp sign-hash with '$hash'"
        cached_otp_sign_hash "$hash"

    else
        error "Unsupported device_type '$device_type'"
        return 2
    fi
}


# --------------------------------------------------------------------
main() {
    # USAGE
    [ "$#" -lt 1 ] && {
        error "No command was given"
        echo "$USAGE" >&2
        exit 1
    }

    command="$1"
    case "$command" in
        # hardware-independent commands -----
        'help')
            echo "$USAGE"
            ;;

        'version')
            echo "$VERSION"
            ;;

        'clear'|'clear-cache'|'cache-clear')
            # cache init set CRYPTO_WRAPPER_ROOT variable
            cache_init
            cache_destroy
            ;;

        # hardware-specific commands --------
        'serial'|'serial-number')
            if [ $# -eq 1 ]; then
                do_serial
            else
                error 'Too many arguments for `serial-number` command'
                return 1
            fi
            ;;

        'sign'|'file-challenge-response')
            if   [ $# -eq 1 ]; then
                # sign the stdin
                do_sign ""
            elif [ $# -eq 2 ]; then
                # sign the given file
                do_sign "$2"
            else
                error 'Too many arguments for `sign` command'
                return 1
            fi
            ;;

        'sign-hash'|'challenge-response')
            if   [ $# -eq 1 ]; then
                error 'Hash is missing for `sign-hash` command'
                return 1
            elif [ $# -eq 2 ]; then
                do_sign_hash "$2"
            else
                error 'Too many arguments for `sign-hash` command'
                return 1
            fi
            ;;

        # -----------------------------------
        *)
            error "Unknown command '$command'"
            exit 1
            ;;

    esac
}


# --------------------------------------------------------------------
main "$@"
