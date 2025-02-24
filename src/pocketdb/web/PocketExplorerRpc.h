// Copyright (c) 2018-2022 The Pocketnet developers
// Distributed under the Apache 2.0 software license, see the accompanying
// https://www.apache.org/licenses/LICENSE-2.0

#ifndef SRC_POCKETEXPLORERRPC_H
#define SRC_POCKETEXPLORERRPC_H

#include "rpc/server.h"
#include "rpc/blockchain.h"
#include "validation.h"
#include "univalue/include/univalue.h"

namespace PocketWeb::PocketWebRpc
{
    using namespace PocketDb;
    using namespace std;

    UniValue GetStatisticByHours(const JSONRPCRequest& request);
    UniValue GetStatisticByDays(const JSONRPCRequest& request);
    UniValue GetStatisticContentByHours(const JSONRPCRequest& request);
    UniValue GetStatisticContentByDays(const JSONRPCRequest& request);
    UniValue GetLastBlocks(const JSONRPCRequest& request);
    UniValue GetCompactBlock(const JSONRPCRequest& request);
    UniValue GetAddressInfo(const JSONRPCRequest& request);
    UniValue GetBalanceHistory(const JSONRPCRequest& request);
    UniValue SearchByHash(const JSONRPCRequest& request);
    UniValue GetAddressTransactions(const JSONRPCRequest& request);
    UniValue GetBlockTransactions(const JSONRPCRequest& request);
    UniValue GetTransaction(const JSONRPCRequest& request);
    UniValue GetTransactions(const JSONRPCRequest& request);

    UniValue _constructTransaction(const PTransactionRef& ptx);
}


#endif //SRC_POCKETEXPLORERRPC_H
