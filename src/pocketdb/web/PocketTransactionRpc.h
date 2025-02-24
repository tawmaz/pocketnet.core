// Copyright (c) 2018-2022 The Pocketnet developers
// Distributed under the Apache 2.0 software license, see the accompanying
// https://www.apache.org/licenses/LICENSE-2.0

#ifndef SRC_POCKETTRANSACTIONRPC_H
#define SRC_POCKETTRANSACTIONRPC_H

#include "rpc/server.h"
#include "wallet/rpcwallet.h"
#include "wallet/wallet.h"
#include "init.h"
#include "validation.h"
#include "consensus/validation.h"
#include "validationinterface.h"
#include "txmempool.h"
#include "rpc/mining.h"
#include "policy/rbf.h"
#include "utilstrencodings.h"
#include "keystore.h"
#include "rpc/rawtransaction.h"
#include "pocketdb/services/Serializer.h"
#include "pocketdb/consensus/Base.h"
#include "pocketdb/consensus/Helper.h"

namespace PocketWeb::PocketWebRpc
{
    UniValue _accept_transaction(const CTransactionRef& tx, const PTransactionRef& ptx);
    UniValue AddTransaction(const JSONRPCRequest& request);
    UniValue EstimateSmartFee(const JSONRPCRequest& request);
    UniValue GenerateTransaction(const JSONRPCRequest& request);
    UniValue GenerateAddress(const JSONRPCRequest& request);
}

#endif //SRC_POCKETTRANSACTIONRPC_H
