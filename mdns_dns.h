#ifndef MDNS_DNS_H
#define MDNS_DNS_H

#include <string.h>

struct mdns_record
{
    char name[256];
    int type;
    int rdata_offset;
    int rdlength;
    int next_offset;
};

static int decode_dns_name(const unsigned char* msg, int msglen, int offset, char* out, int outlen)
{
    int pos         = offset;
    int consumed    = 0;
    int outpos      = 0;
    int name_length = 1;

    if (!msg || !out || msglen <= 0 || offset < 0 || offset >= msglen || outlen <= 0)
    {
        return -1;
    }
    out[0] = '\0';

    for (int steps = 0; steps < msglen; ++steps)
    {
        if (pos < 0 || pos >= msglen)
            return -1;

        unsigned char c = msg[pos];
        if (c == 0)
        {
            if (!consumed)
                consumed = pos - offset + 1;
            out[outpos] = '\0';
            return consumed;
        }
        if ((c & 0xC0) == 0xC0)
        {
            if (pos + 1 >= msglen)
                return -1;
            int ptr = ((c & 0x3F) << 8) | msg[pos + 1];
            if (ptr >= msglen)
                return -1;
            if (!consumed)
                consumed = pos - offset + 2;
            pos = ptr;
            continue;
        }
        if ((c & 0xC0) != 0)
            return -1;

        pos++;
        if (c > msglen - pos || name_length + c + 1 > 255 || outpos + (outpos ? 1 : 0) + c >= outlen)
        {
            return -1;
        }
        if (outpos)
            out[outpos++] = '.';
        memcpy(out + outpos, msg + pos, c);
        outpos += c;
        name_length += c + 1;
        pos += c;
    }
    return -1;
}

static int mdns_next_record(const unsigned char* msg, int msglen, int offset,
    struct mdns_record* record)
{
    if (!record)
        return 0;

    int used = decode_dns_name(msg, msglen, offset, record->name, sizeof(record->name));
    if (used < 0 || used > msglen - offset || msglen - offset - used < 10)
        return 0;

    int pos      = offset + used;
    int rdlength = (msg[pos + 8] << 8) | msg[pos + 9];
    pos += 10;
    if (rdlength > msglen - pos)
        return 0;

    record->type         = (msg[offset + used] << 8) | msg[offset + used + 1];
    record->rdata_offset = pos;
    record->rdlength     = rdlength;
    record->next_offset  = pos + rdlength;
    return 1;
}

#endif
