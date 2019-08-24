#include "callback.h"
#include <cstdio>
#include <cstring>

#include <linux/netfilter.h> /* for NF_ACCEPT */

u_int32_t filter(struct nfq_data *tb, const std::set<std::string> &blacklist)
{
    unsigned char *data;
    int ip_len = nfq_get_payload(tb, &data);

    // IPHeader
    IPHeader *iphdr = reinterpret_cast<IPHeader *>(data);
    if (iphdr->ip_p != IPPROTO_TCP)
        return NF_ACCEPT;

    // TCPHeader
    int tcp_offset = iphdr->ip_hl * 4;
    TCPHeader *tcphdr = reinterpret_cast<TCPHeader *>(data + tcp_offset);

    // HTTPHeader?
    int http_offset = tcp_offset + tcphdr->th_off * 4;
    if (http_offset >= ip_len)
        return NF_ACCEPT;

    // Check HTTP Header
    if (memcmp(data + http_offset, "GET", 3) == 0 || memcmp(data + http_offset, "POST", 4) == 0) {
        char *host = reinterpret_cast<char *>(data + http_offset);
        while (strncmp(host, "Host", 4) != 0)
            host++;
        host += 6; // "Host: " - 6 chars
        std::string hostname;
        while (*host != '\r')
            hostname += *(host++);
        if (blacklist.find(hostname) != blacklist.end()) {
            printf("Blacklist Found: %s\n", hostname.c_str());
            return NF_DROP;
        }
        printf("Blacklist Not Found: %s\n", hostname.c_str());
    }
    return NF_ACCEPT;
}
