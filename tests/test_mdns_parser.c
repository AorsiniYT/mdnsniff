#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../mdns_dns.h"

static void require(int condition, const char* message)
{
    if (!condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void test_names(void)
{
    const unsigned char plain[] = { 3, 'a', 'b', 'c', 5, 'l', 'o', 'c', 'a', 'l', 0 };
    unsigned char pkt[512]      = { 0 };
    char out[256];

    require(decode_dns_name(plain, sizeof(plain), 0, out, sizeof(out)) == (int)sizeof(plain), "plain name length");
    require(strcmp(out, "abc.local") == 0, "plain name contents");

    memcpy(pkt + 12, plain + 4, sizeof(plain) - 4);
    pkt[19] = 3;
    memcpy(pkt + 20, "foo", 3);
    pkt[23] = 0xC0;
    pkt[24] = 12;
    require(decode_dns_name(pkt, 25, 19, out, sizeof(out)) == 6, "compressed name length");
    require(strcmp(out, "foo.local") == 0, "compressed name contents");

    pkt[12] = 0xC0;
    pkt[13] = 12;
    require(decode_dns_name(pkt, 14, 12, out, sizeof(out)) < 0, "self pointer");
    pkt[13] = 14;
    pkt[14] = 0xC0;
    pkt[15] = 12;
    require(decode_dns_name(pkt, 16, 12, out, sizeof(out)) < 0, "pointer cycle");
    require(decode_dns_name(pkt, 13, 12, out, sizeof(out)) < 0, "truncated pointer");
    pkt[13] = 0xFF;
    require(decode_dns_name(pkt, 14, 12, out, sizeof(out)) < 0, "pointer out of bounds");
    pkt[12] = 0x40;
    require(decode_dns_name(pkt, 14, 12, out, sizeof(out)) < 0, "reserved label type");
    pkt[12] = 0x80;
    require(decode_dns_name(pkt, 14, 12, out, sizeof(out)) < 0, "reserved label type 2");
    const unsigned char short_label[] = { 3, 'a', 'b' };
    require(decode_dns_name(short_label, sizeof(short_label), 0, out, sizeof(out)) < 0, "truncated label");
    require(decode_dns_name(plain, sizeof(plain), 0, out, 4) < 0, "small output buffer");

    memset(pkt, 0, sizeof(pkt));
    int pos = 0;
    for (int i = 0; i < 3; ++i)
    {
        pkt[pos++] = 63;
        memset(pkt + pos, 'x', 63);
        pos += 63;
    }
    pkt[pos++] = 61;
    memset(pkt + pos, 'y', 61);
    pos += 61;
    pkt[pos++] = 0;
    require(decode_dns_name(pkt, pos, 0, out, sizeof(out)) == pos, "maximum DNS name");
    pos = 0;
    for (int i = 0; i < 4; ++i)
    {
        pkt[pos++] = 63;
        memset(pkt + pos, 'z', 63);
        pos += 63;
    }
    pkt[pos++] = 0;
    require(decode_dns_name(pkt, pos, 0, out, sizeof(out)) < 0, "oversized DNS name");
}

static void test_records(void)
{
    unsigned char pkt[64] = { 0 };
    struct mdns_record rr;
    pkt[12] = 0;
    pkt[13] = 0;
    pkt[14] = 33;
    pkt[15] = 0;
    pkt[16] = 1;
    pkt[21] = 0;
    pkt[22] = 7;
    pkt[27] = 0x12;
    pkt[28] = 0x34;
    pkt[29] = 0;
    require(mdns_next_record(pkt, 30, 12, &rr), "valid SRV record");
    require(rr.type == 33 && rr.rdata_offset == 23 && rr.rdlength == 7 && rr.next_offset == 30,
        "SRV record offsets");
    require(decode_dns_name(pkt, 30, rr.rdata_offset + 6, rr.name, sizeof(rr.name)) == 1,
        "valid SRV target");
    require(!mdns_next_record(pkt, 29, 12, &rr), "truncated RDATA");
    require(!mdns_next_record(pkt, 22, 12, &rr), "truncated RR header");
    pkt[12] = 0xC0;
    pkt[13] = 12;
    require(!mdns_next_record(pkt, 30, 12, &rr), "cyclic owner");
}

static void test_random_packets(void)
{
    unsigned int state = 0xC035C035;
    unsigned char pkt[128];
    char out[256];
    struct mdns_record rr;

    for (int i = 0; i < 30000; ++i)
    {
        int len = (i % (int)sizeof(pkt)) + 1;
        for (int j = 0; j < len; ++j)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            pkt[j] = (unsigned char)state;
        }
        int offset = (i / 13) % len;
        int n      = decode_dns_name(pkt, len, offset, out, sizeof(out));
        require(n < 0 || (n > 0 && n <= len - offset), "fuzzed name length");
        if (mdns_next_record(pkt, len, offset, &rr))
        {
            require(rr.rdata_offset >= offset && rr.next_offset <= len && rr.next_offset == rr.rdata_offset + rr.rdlength,
                "fuzzed record bounds");
        }
    }
}

int main(void)
{
    test_names();
    test_records();
    test_random_packets();
    puts("mDNS parser regression tests passed");
    return 0;
}
