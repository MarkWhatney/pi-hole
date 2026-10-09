#!/usr/bin/env bash

# Pi-hole: A black hole for Internet advertisements
# (c) 2017 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# Detect domains that contain Cyrillic characters, and read or write the
# dns.blocking.cyrillic setting through FTL.
#
# Query-time blocking is not implemented here. FTL owns the DNS path and
# pihole.toml. This file is the core-side contract and the reference
# detector used by `pihole cyrillic check`. See docs/cyrillic-blocking.md.
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

# FTL config key. Absent or unrecognized means the feature is off.
CYRILLIC_BLOCKING_KEY="dns.blocking.cyrillic"

#######################
# Return 0 when the Unicode code point is in a Cyrillic block:
#   U+0400..U+04FF  Cyrillic
#   U+0500..U+052F  Cyrillic Supplement
#   U+2DE0..U+2DFF  Cyrillic Extended-A
#   U+A640..U+A69F  Cyrillic Extended-B
#   U+1C80..U+1C8F  Cyrillic Extended-C
#######################
_cyr_codepoint_is_cyrillic() {
    local cp="$1"

    if (( cp >= 0x400 && cp <= 0x4FF )); then
        return 0
    fi
    if (( cp >= 0x500 && cp <= 0x52F )); then
        return 0
    fi
    if (( cp >= 0x2DE0 && cp <= 0x2DFF )); then
        return 0
    fi
    if (( cp >= 0xA640 && cp <= 0xA69F )); then
        return 0
    fi
    if (( cp >= 0x1C80 && cp <= 0x1C8F )); then
        return 0
    fi
    return 1
}

#######################
# Store the unsigned byte value of one C-locale character in _cyr_byte.
#######################
_cyr_set_byte() {
    local char="$1"

    if [ "${char}" = "'" ]; then
        _cyr_byte=39
        return 0
    fi
    printf -v _cyr_byte '%d' "'${char}"
}

#######################
# Fill _cyr_bytes with the unsigned byte values of a string.
# Caller must be in the C locale so indexing is by byte.
#######################
_cyr_collect_bytes() {
    local text="$1"
    local i char len

    _cyr_bytes=()
    len=${#text}
    for ((i = 0; i < len; i++)); do
        char=${text:i:1}
        _cyr_set_byte "${char}"
        _cyr_bytes+=("${_cyr_byte}")
    done
}

#######################
# Return 0 when a UTF-8 byte string contains a Cyrillic code point.
# Invalid and overlong sequences are skipped. They are not Cyrillic.
#######################
_cyr_bytes_have_cyrillic() {
    local i=0
    local n=${#_cyr_bytes[@]}
    local b c1 c2 c3 cp

    while (( i < n )); do
        b=${_cyr_bytes[i]}
        cp=-1

        if (( b < 0x80 )); then
            cp=${b}
            i=$((i + 1))
        elif (( (b & 0xE0) == 0xC0 )); then
            if (( i + 1 >= n )); then
                return 1
            fi
            c1=${_cyr_bytes[i + 1]}
            if (( (c1 & 0xC0) != 0x80 )); then
                i=$((i + 1))
                continue
            fi
            cp=$(( ((b & 0x1F) << 6) | (c1 & 0x3F) ))
            # Reject overlong encodings.
            if (( cp < 0x80 )); then
                cp=-1
            fi
            i=$((i + 2))
        elif (( (b & 0xF0) == 0xE0 )); then
            if (( i + 2 >= n )); then
                return 1
            fi
            c1=${_cyr_bytes[i + 1]}
            c2=${_cyr_bytes[i + 2]}
            if (( (c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 )); then
                i=$((i + 1))
                continue
            fi
            cp=$(( ((b & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F) ))
            if (( cp < 0x800 )); then
                cp=-1
            fi
            i=$((i + 3))
        elif (( (b & 0xF8) == 0xF0 )); then
            if (( i + 3 >= n )); then
                return 1
            fi
            c1=${_cyr_bytes[i + 1]}
            c2=${_cyr_bytes[i + 2]}
            c3=${_cyr_bytes[i + 3]}
            if (( (c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80 )); then
                i=$((i + 1))
                continue
            fi
            cp=$(( ((b & 0x07) << 18) | ((c1 & 0x3F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F) ))
            if (( cp < 0x10000 || cp > 0x10FFFF )); then
                cp=-1
            fi
            i=$((i + 4))
        else
            i=$((i + 1))
            continue
        fi

        if (( cp >= 0 )) && _cyr_codepoint_is_cyrillic "${cp}"; then
            return 0
        fi
    done
    return 1
}

#######################
# RFC 3492 digit value for one ASCII punycode character.
#######################
_cyr_puny_digit() {
    case "$1" in
        a|A) printf '%s\n' 0 ;;
        b|B) printf '%s\n' 1 ;;
        c|C) printf '%s\n' 2 ;;
        d|D) printf '%s\n' 3 ;;
        e|E) printf '%s\n' 4 ;;
        f|F) printf '%s\n' 5 ;;
        g|G) printf '%s\n' 6 ;;
        h|H) printf '%s\n' 7 ;;
        i|I) printf '%s\n' 8 ;;
        j|J) printf '%s\n' 9 ;;
        k|K) printf '%s\n' 10 ;;
        l|L) printf '%s\n' 11 ;;
        m|M) printf '%s\n' 12 ;;
        n|N) printf '%s\n' 13 ;;
        o|O) printf '%s\n' 14 ;;
        p|P) printf '%s\n' 15 ;;
        q|Q) printf '%s\n' 16 ;;
        r|R) printf '%s\n' 17 ;;
        s|S) printf '%s\n' 18 ;;
        t|T) printf '%s\n' 19 ;;
        u|U) printf '%s\n' 20 ;;
        v|V) printf '%s\n' 21 ;;
        w|W) printf '%s\n' 22 ;;
        x|X) printf '%s\n' 23 ;;
        y|Y) printf '%s\n' 24 ;;
        z|Z) printf '%s\n' 25 ;;
        0) printf '%s\n' 26 ;;
        1) printf '%s\n' 27 ;;
        2) printf '%s\n' 28 ;;
        3) printf '%s\n' 29 ;;
        4) printf '%s\n' 30 ;;
        5) printf '%s\n' 31 ;;
        6) printf '%s\n' 32 ;;
        7) printf '%s\n' 33 ;;
        8) printf '%s\n' 34 ;;
        9) printf '%s\n' 35 ;;
        *) return 1 ;;
    esac
}

#######################
# RFC 3492 bias adaptation. Prints the new bias.
#######################
_cyr_puny_adapt() {
    local delta="$1"
    local numpoints="$2"
    local firsttime="$3"
    local base=36 tmin=1 tmax=26 skew=38 damp=700 k=0

    if (( firsttime )); then
        delta=$((delta / damp))
    else
        delta=$((delta / 2))
    fi
    delta=$((delta + (delta / numpoints)))
    while (( delta > ((base - tmin) * tmax) / 2 )); do
        delta=$((delta / (base - tmin)))
        k=$((k + base))
    done
    printf '%s\n' $(( k + (((base - tmin + 1) * delta) / (delta + skew)) ))
}

#######################
# Decode one punycode label body (the text after "xn--") into _cyr_cps.
# Implements RFC 3492. Returns 1 on overflow or malformed input.
# A failed decode is not treated as Cyrillic.
#######################
_cyr_punycode_decode() {
    local input="$1"
    local base=36 tmin=1 tmax=26
    local n=128 i=0 bias=72
    local len delim=-1 p char ord
    local pos inlen oldi w k digit t outlen delta firsttime
    local max_int=9223372036854775807
    local -a basic=()

    _cyr_cps=()
    # Punycode digits are case-insensitive. Basic code points keep the case
    # they were stored with; _cyr_puny_digit accepts both cases.
    len=${#input}

    for ((p = 0; p < len; p++)); do
        char=${input:p:1}
        if [ "${char}" = "-" ]; then
            delim=${p}
        fi
    done

    if (( delim >= 0 )); then
        for ((p = 0; p < delim; p++)); do
            char=${input:p:1}
            _cyr_set_byte "${char}"
            ord=${_cyr_byte}
            if (( ord >= 128 )); then
                return 1
            fi
            basic+=("${ord}")
        done
        input=${input:delim+1}
    fi

    if (( ${#basic[@]} > 0 )); then
        _cyr_cps=("${basic[@]}")
    fi

    pos=0
    inlen=${#input}
    while (( pos < inlen )); do
        oldi=${i}
        w=1
        k=${base}
        while true; do
            if (( pos >= inlen )); then
                return 1
            fi
            char=${input:pos:1}
            pos=$((pos + 1))
            if ! digit=$(_cyr_puny_digit "${char}"); then
                return 1
            fi
            if (( digit > 0 && w > 0 && digit > (max_int / w) )); then
                return 1
            fi
            if (( i > max_int - (digit * w) )); then
                return 1
            fi
            i=$((i + (digit * w)))
            if (( k <= bias )); then
                t=${tmin}
            elif (( k >= bias + tmax )); then
                t=${tmax}
            else
                t=$((k - bias))
            fi
            if (( digit < t )); then
                break
            fi
            if (( (base - t) <= 0 || w > (max_int / (base - t)) )); then
                return 1
            fi
            w=$((w * (base - t)))
            k=$((k + base))
            if (( k > 100000 )); then
                return 1
            fi
        done

        outlen=$((${#_cyr_cps[@]} + 1))
        delta=$((i - oldi))
        if (( oldi == 0 )); then
            firsttime=1
        else
            firsttime=0
        fi
        bias=$(_cyr_puny_adapt "${delta}" "${outlen}" "${firsttime}")
        if (( i / outlen > max_int - n )); then
            return 1
        fi
        n=$((n + (i / outlen)))
        if (( n < 0 || n > 0x10FFFF )); then
            return 1
        fi
        i=$((i % outlen))
        if (( ${#_cyr_cps[@]} == 0 )); then
            _cyr_cps=("${n}")
        else
            _cyr_cps=("${_cyr_cps[@]:0:i}" "${n}" "${_cyr_cps[@]:i}")
        fi
        i=$((i + 1))
        if (( ${#_cyr_cps[@]} > 256 )); then
            return 1
        fi
    done
    return 0
}

#######################
# Return 0 when any decoded code point is Cyrillic.
#######################
_cyr_codepoints_have_cyrillic() {
    local cp

    for cp in "${_cyr_cps[@]}"; do
        if _cyr_codepoint_is_cyrillic "${cp}"; then
            return 0
        fi
    done
    return 1
}

#######################
# Write the UTF-8 encoding of one Unicode code point to stdout.
#######################
_cyr_cp_to_utf8() {
    local cp="$1"
    local b0 b1 b2 b3

    if (( cp < 0x80 )); then
        printf -v b0 '\\%03o' "${cp}"
        printf '%b' "${b0}"
    elif (( cp < 0x800 )); then
        printf -v b0 '\\%03o' $(( 0xC0 | (cp >> 6) ))
        printf -v b1 '\\%03o' $(( 0x80 | (cp & 0x3F) ))
        printf '%b%b' "${b0}" "${b1}"
    elif (( cp < 0x10000 )); then
        printf -v b0 '\\%03o' $(( 0xE0 | (cp >> 12) ))
        printf -v b1 '\\%03o' $(( 0x80 | ((cp >> 6) & 0x3F) ))
        printf -v b2 '\\%03o' $(( 0x80 | (cp & 0x3F) ))
        printf '%b%b%b' "${b0}" "${b1}" "${b2}"
    else
        printf -v b0 '\\%03o' $(( 0xF0 | (cp >> 18) ))
        printf -v b1 '\\%03o' $(( 0x80 | ((cp >> 12) & 0x3F) ))
        printf -v b2 '\\%03o' $(( 0x80 | ((cp >> 6) & 0x3F) ))
        printf -v b3 '\\%03o' $(( 0x80 | (cp & 0x3F) ))
        printf '%b%b%b%b' "${b0}" "${b1}" "${b2}" "${b3}"
    fi
}

#######################
# Split a domain on ASCII dots into _cyr_labels.
#######################
_cyr_split_labels() {
    local rest="$1"
    local label

    _cyr_labels=()
    while [ -n "${rest}" ]; do
        case "${rest}" in
            *.*)
                label="${rest%%.*}"
                rest="${rest#*.}"
                _cyr_labels+=("${label}")
                ;;
            *)
                _cyr_labels+=("${rest}")
                rest=""
                ;;
        esac
    done
}

#######################
# Return 0 if the domain contains a Cyrillic code point.
# Return 1 if it does not.
# Return 2 if the domain is empty.
#
# ACE labels (xn--, case-insensitive) are decoded with RFC 3492 and the
# resulting code points are tested. Every other label is scanned as UTF-8,
# so a domain typed as Unicode is detected as well. A punycode label that
# fails to decode is not Cyrillic by itself.
#
# Example: domain_contains_cyrillic "xn--e1afmkfd.com"
#######################
domain_contains_cyrillic() {
    local LC_ALL=C
    local domain="${1-}"
    local label label_lc body

    while [ -n "${domain}" ] && [ "${domain}" != "${domain%.}" ]; do
        domain="${domain%.}"
    done
    if [ -z "${domain}" ]; then
        return 2
    fi

    _cyr_split_labels "${domain}"
    for label in "${_cyr_labels[@]}"; do
        if [ -z "${label}" ]; then
            continue
        fi
        # LC_ALL=C is set by the caller, so this folds ASCII only.
        label_lc=$(printf '%s' "${label}" | tr '[:upper:]' '[:lower:]')
        case "${label_lc}" in
            xn--*)
                body="${label_lc#xn--}"
                if _cyr_punycode_decode "${body}" && _cyr_codepoints_have_cyrillic; then
                    return 0
                fi
                ;;
            *)
                _cyr_collect_bytes "${label}"
                if _cyr_bytes_have_cyrillic; then
                    return 0
                fi
                ;;
        esac
    done
    return 1
}

#######################
# Decode a punycode label body (without the xn-- prefix) and print UTF-8.
# Returns 1 when the input is not valid punycode.
#
# Example: punycode_decode_label "e1afmkfd"
#######################
punycode_decode_label() {
    local LC_ALL=C
    local cp

    if ! _cyr_punycode_decode "${1-}"; then
        return 1
    fi
    for cp in "${_cyr_cps[@]}"; do
        _cyr_cp_to_utf8 "${cp}"
    done
}

#######################
# Print one FTL config value with ANSI color and surrounding whitespace removed.
#######################
_cyr_clean_ftl_output() {
    local text="$1"
    local re

    text="${text//$'\r'/}"
    re=$'\033''\[[0-9;]*[A-Za-z]'
    while [[ "${text}" =~ ${re} ]]; do
        text="${text//"${BASH_REMATCH[0]}"/}"
    done
    text="${text#"${text%%[![:space:]]*}"}"
    text="${text%"${text##*[![:space:]]}"}"
    printf '%s' "${text}"
}

#######################
# Return 0 when FTL output says it does not know the config key.
#######################
_cyr_ftl_output_is_unknown_key() {
    local LC_ALL=C
    local text="$1"

    text=$(printf '%s' "${text}" | tr '[:upper:]' '[:lower:]')
    case "${text}" in
        *unknown\ config*|*unknown\ option*|*not\ a\ known*|*command\ not\ found*|*no\ such\ file*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

#######################
# Print the effective state of dns.blocking.cyrillic.
# A missing FTL binary or an FTL build that rejects the key is off.
# Always returns 0: the reported state is the effective state.
#######################
cyrillic_blocking_status() {
    local output err=0 cleaned

    if ! command -v pihole-FTL >/dev/null 2>&1; then
        printf '%s\n' "Cyrillic domain blocking is disabled."
        printf '%s\n' "FTL does not recognize ${CYRILLIC_BLOCKING_KEY} yet."
        return 0
    fi

    output="$(pihole-FTL --config -q "${CYRILLIC_BLOCKING_KEY}" 2>&1)" || err=$?
    cleaned=$(_cyr_clean_ftl_output "${output}")
    if [ "${err}" -eq 0 ] && [ "${cleaned}" = "true" ]; then
        printf '%s\n' "Cyrillic domain blocking is enabled."
        return 0
    fi
    if [ "${err}" -eq 0 ] && [ "${cleaned}" = "false" ]; then
        printf '%s\n' "Cyrillic domain blocking is disabled."
        return 0
    fi

    printf '%s\n' "Cyrillic domain blocking is disabled."
    printf '%s\n' "FTL does not recognize ${CYRILLIC_BLOCKING_KEY} yet."
    return 0
}

#######################
# Set dns.blocking.cyrillic to true or false through pihole-FTL.
# Returns 0 when FTL stored the value.
# Returns 1 when FTL rejected the key or the write failed. The option
# stays at its previous effective state (off, on stock FTL).
#
# Example: cyrillic_blocking_set true
#######################
cyrillic_blocking_set() {
    local desired="$1"
    local output err=0 cleaned word

    case "${desired}" in
        true|false) ;;
        *)
            printf '%s\n' "Invalid Cyrillic blocking value '${desired}'."
            return 1
            ;;
    esac

    if [ "${desired}" = "true" ]; then
        word="enabled"
    else
        word="disabled"
    fi

    if ! command -v pihole-FTL >/dev/null 2>&1; then
        printf '  %s FTL does not recognize %s yet, so Cyrillic domain blocking stays disabled.\n' "${CROSS:-[✗]}" "${CYRILLIC_BLOCKING_KEY}"
        printf '  %s Query blocking for this option has to be implemented in FTL. See docs/cyrillic-blocking.md.\n' "${INFO:-[i]}"
        return 1
    fi

    output="$(pihole-FTL --config "${CYRILLIC_BLOCKING_KEY}" "${desired}" 2>&1)" || err=$?
    cleaned=$(_cyr_clean_ftl_output "${output}")
    if [ "${err}" -eq 0 ]; then
        printf '  %s Cyrillic domain blocking has been %s (%s=%s).\n' "${TICK:-[✓]}" "${word}" "${CYRILLIC_BLOCKING_KEY}" "${desired}"
        return 0
    fi

    if _cyr_ftl_output_is_unknown_key "${cleaned}"; then
        printf '  %s FTL does not recognize %s yet, so Cyrillic domain blocking stays disabled.\n' "${CROSS:-[✗]}" "${CYRILLIC_BLOCKING_KEY}"
        printf '  %s Query blocking for this option has to be implemented in FTL. See docs/cyrillic-blocking.md.\n' "${INFO:-[i]}"
        return 1
    fi

    printf '  %s Failed to set %s.\n' "${CROSS:-[✗]}" "${CYRILLIC_BLOCKING_KEY}"
    if [ -n "${cleaned}" ]; then
        printf '%s\n' "${cleaned}"
    fi
    return 1
}
