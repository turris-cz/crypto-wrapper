#!/bin/sh
# busybox POSIX-like shell script
set -eu

# protect cache files from other users
umask 0077

VERSION='0.2'
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
                    Print this message end exit

        $SCRIPTNAME version
                    Print script version and exit

        $SCRIPTNAME serial-number
                    Print serial number of the device

        $SCRIPTNAME mac-address
                    Print MAC address of the device

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
    printf '%s: %s: %s\n' "$SCRIPTNAME" "$1" "$2" >&2
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
# checks existence and readability of file $1
check_file() {
    local file=$1

    [ -f "$file" -a -r "$file" ] || {
        error "'$file' is not a readable file"
        return 1
    }
}

# check hexstring $1 of given length $2
check_hexstring() {
    local hash=$1
    local length=$2

    [ -z "$(printf '%s\n' "$hash" | tr -d '0-9a-f')" ] || {
        error 'Given hash is not hexadecimal string'
        return 1
    }

    [ "${#hash}" -eq "$length" ] || {
        error "Given hash must have $length hexadecimal characters"
        return 1
    }
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
    local hash
    hash=$(hash_string "$value")

    # key is read first so hash must be written before the key
    printf '%s\n' "$value" > "$CRYPTO_WRAPPER_ROOT/hash_$hash"
    printf '%s\n' "$value" > "$CRYPTO_WRAPPER_ROOT/key_$key"
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
    local key_file="$CRYPTO_WRAPPER_ROOT/key_$key"
    local hash hash_file value

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

    printf '%s\n' "$value"
}


# get value from cache for the key reffered in file $1
cache_get_file() {
    local file="$1"
    local key value

    key=$(hash_file "$file")
    value=$(cache_get "$key") || {
        debug "Value for file '$file' was not found in cache"
        return 1
    }

    printf '%s\n' "$value"
}


# get value from cache for the key reffered in $1 string
cache_get_string() {
    local string="$1"
    local key value

    key=$(hash_string "$string")
    value=$(cache_get "$key") || {
        debug "Value for string '$string' was not found in cache"
        return 1
    }

    printf '%s\n' "$value"
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

    printf '%s\n' "$output"
}


cached_atsha_serial() {
    cached_command string 'serial' 'atsha204cmd' 'serial-number'
}


cached_atsha_mac() {
    cached_command string 'mac' 'atsha204cmd' 'mac' '1'
}


# 64-bytes hex string from stdin
cached_atsha_challenge_response() {
    local hash="$1"
    check_hexstring "$hash" "$HASH_LENGTH_ATSHA"

    printf '%s\n' "$hash" \
            | cached_command string "$hash" 'atsha204cmd' 'challenge-response'
}


cached_atsha_challenge_response_file() {
    local file="$1"
    check_file "$file"

    # this is wierd atsha204cmd interface
    printf '%s\n' "$file" \
            | cached_command file "$file" 'atsha204cmd' 'file-challenge-response'
}


cached_otp_serial() {
    cached_command string 'serial' 'mox-otp' 'serial-number'
}


cached_otp_mac() {
    cached_command string 'mac' 'mox-otp' 'mac-address'
}


# 128-bytes hex string from stdin
cached_otp_sign_hash() {
    local hash="$1"
    check_hexstring "$hash" "$HASH_LENGTH_OTP"

    cached_command string "$hash" 'mox-otp' 'sign-hash' "$hash"
}


cached_otp_sign() {
    local file="$1"
    check_file "$file"

    cached_command file "$file" 'mox-otp' 'sign' "$file"
}


# --------------------------------------------------------------------
get_device_type(){
    local model

    [ -f "$SYSINFO_MODEL_FILE" ] || {
        error "Unknown device model; sysinfo file ($SYSINFO_MODEL_FILE) is missing"
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
    local device_type serial
    cache_init

    device_type=$(get_device_type)
    if   [ "$device_type" = "$TYPE_ATSHA" ]; then
        debug "Call atsha serial-number"
        serial=$(cached_atsha_serial)

    elif [ "$device_type" = "$TYPE_OTP" ]; then
        debug "Call otp serial-number"
        serial=$(cached_otp_serial)

    else
        error "Unsupported device_type '$device_type'"
        return 2
    fi

    printf '%s\n' "$serial" | tr 'a-z' 'A-Z'
}


do_mac() {
    local device_type mac
    cache_init

    device_type=$(get_device_type)
    if   [ "$device_type" = "$TYPE_ATSHA" ]; then
        debug "Call atsha mac"
        mac=$(cached_atsha_mac)

    elif [ "$device_type" = "$TYPE_OTP" ]; then
        debug "Call otp mac-address"
        mac=$(cached_otp_mac)

    else
        error "Unsupported device_type '$device_type'"
        return 2
    fi

    printf '%s\n' "$mac" | tr 'A-Z' 'a-z'
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
    local hash device_type
    hash=$(printf '%s\n' "$1" | head -n 1 | tr 'A-Z' 'a-z')
    cache_init

    device_type=$(get_device_type)
    if   [ "$device_type" = "$TYPE_ATSHA" ]; then
        debug "Call atsha challenge-response with '$hash'"
        cached_atsha_challenge_response "$hash"

    elif [ "$device_type" = "$TYPE_OTP" ]; then
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

        'mac'|'mac-address')
            if [ $# -eq 1 ]; then
                do_mac
            else
                error 'Too many arguments for `mac-address` command'
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
