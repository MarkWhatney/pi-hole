#!/usr/bin/env bats
# Tests for Cyrillic domain detection and the pihole cyrillic command.

load 'libs/bats-support/load'
load 'libs/bats-assert/load'
load 'bats_helper.bash'

@test "punycode_decode_label decodes Cyrillic, German, and Chinese labels" {
    run bash -c '
        source /opt/pihole/cyrillic.sh
        got=$(punycode_decode_label e1afmkfd; printf x)
        want=$(printf "\320\277\321\200\320\270\320\274\320\265\321\200x")
        [ "$got" = "$want" ] || exit 1
        got=$(punycode_decode_label "Mnchen-3ya"; printf x)
        want=$(printf "M\303\274nchenx")
        [ "$got" = "$want" ] || exit 2
        got=$(punycode_decode_label fiqs8s; printf x)
        want=$(printf "\344\270\255\345\233\275x")
        [ "$got" = "$want" ] || exit 3
        if punycode_decode_label "***"; then
            exit 4
        fi
        printf ok
    '
    assert_success
    assert_output "ok"
}

@test "Cyrillic code points are detected and neighboring blocks are not" {
    run bash -c '
        source /opt/pihole/cyrillic.sh
        expect_domain() {
            local domain="$1" want="$2" got
            domain_contains_cyrillic "${domain}"
            got=$?
            if [ "${got}" -ne "${want}" ]; then
                printf "FAIL %s got %s want %s\n" "${domain}" "${got}" "${want}"
                exit 1
            fi
        }
        # Cyrillic block edges and a real label
        expect_domain xn--vza 0
        expect_domain xn--56a 0
        expect_domain xn--e1afmkfd.com 0
        expect_domain XN--E1AFMKFD.COM. 0
        expect_domain xn--d1acufc.xn--p1ai 0
        expect_domain xn--ggle-55da.com 0
        expect_domain xn--googl-3we.example 0
        expect_domain safe.xn--e1a.org 0
        expect_domain "xn--***.xn--e1a" 0
        # Supplement, Extended-A/B/C edges
        expect_domain xn--66a 0
        expect_domain xn--j8a 0
        expect_domain xn--5qj 0
        expect_domain xn--1rj 0
        expect_domain xn--mw8a 0
        expect_domain xn--cz8a 0
        expect_domain xn--23f 0
        expect_domain xn--i4f 0
        # Just outside each block, plus non-Cyrillic IDNs
        expect_domain xn--uza 1
        expect_domain xn--k8a 1
        expect_domain xn--4qj 1
        expect_domain xn--2rj 1
        expect_domain xn--lw8a 1
        expect_domain xn--dz8a 1
        expect_domain xn--13f 1
        expect_domain xn--j4f 1
        expect_domain example.com 1
        expect_domain example.com. 1
        expect_domain example..com 1
        expect_domain xn--mnchen-3ya.de 1
        expect_domain xn--fiqs8s 1
        expect_domain xn--caf-dma.fr 1
        expect_domain "xn--***" 1
        expect_domain xn-- 1
        expect_domain "" 2
        expect_domain . 2
        # Raw UTF-8: пример.com, ПРИМЕР.example, münchen.de, an emoji label
        expect_domain "$(printf "\320\277\321\200\320\270\320\274\320\265\321\200.com")" 0
        expect_domain "$(printf "\320\237\320\240\320\230\320\234\320\225\320\240.example")" 0
        expect_domain "$(printf "m\303\274nchen.de")" 1
        expect_domain "$(printf "\360\237\230\200.com")" 1
        printf ok
    '
    assert_success
    assert_output "ok"
}

@test "pihole cyrillic check matches punycode and rejects other IDNs" {
    run pihole cyrillic check xn--e1afmkfd.com
    assert_success
    assert_output "xn--e1afmkfd.com contains Cyrillic characters."

    run pihole cyrillic check xn--mnchen-3ya.de
    assert_failure
    assert_output "xn--mnchen-3ya.de has no Cyrillic characters."

    run pihole cyrillic check
    [ "${status}" -eq 2 ]

    run pihole cyrillic check example.com extra.example
    [ "${status}" -eq 2 ]
}

@test "pihole cyrillic help is wired into the command" {
    run pihole cyrillic --help
    assert_success
    assert_output --partial "dns.blocking.cyrillic"
    assert_output --partial "disabled by default"

    run pihole --help
    assert_success
    assert_output --partial "cyrillic"

    run pihole cyrillic
    assert_success
    assert_output --partial "dns.blocking.cyrillic"

    run pihole cyrillic not-a-mode
    assert_failure
    assert_output --partial "Invalid option"
}

@test "status stays disabled when FTL does not know the key" {
    if command -v pihole-FTL >/dev/null 2>&1; then
        skip "pihole-FTL is installed; this case is for builds that lack dns.blocking.cyrillic"
    fi

    run pihole cyrillic status
    assert_success
    assert_output --partial "Cyrillic domain blocking is disabled."
    assert_output --partial "does not recognize dns.blocking.cyrillic"
}

@test "cyrillic on refuses to run without root" {
    if [ "$(id -u)" -eq 0 ]; then
        run su -s /bin/bash nobody -c "PATH='${PATH}' pihole cyrillic on"
    else
        run pihole cyrillic on
    fi
    assert_failure
    assert_output --partial "requires root"
}

@test "setting the option fails closed when FTL does not know the key" {
    if [ "$(id -u)" -ne 0 ]; then
        skip "config writes are root-only; the root image covers the FTL rejection"
    fi
    if command -v pihole-FTL >/dev/null 2>&1; then
        skip "pihole-FTL is installed; this case is for builds that lack dns.blocking.cyrillic"
    fi

    run pihole cyrillic on
    assert_failure
    assert_output --partial "does not recognize dns.blocking.cyrillic"
    refute_output --partial "has been enabled"

    run pihole cyrillic off
    assert_failure
    assert_output --partial "does not recognize dns.blocking.cyrillic"
}
