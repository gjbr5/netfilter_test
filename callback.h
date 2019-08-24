#ifndef CALLBACK_H
#define CALLBACK_H

#include "pkt_hdr.h"

#include <set>
#include <string>

#include <libnetfilter_queue/libnetfilter_queue.h>

u_int32_t filter(struct nfq_data *tb, const std::set<std::string> &blacklist);

#endif // CALLBACK_H
