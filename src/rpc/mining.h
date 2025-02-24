// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef POCKETCOIN_RPC_MINING_H
#define POCKETCOIN_RPC_MINING_H

#include <script/script.h>

#include <univalue.h>
#include <rpc/server.h>

/** Generate blocks (mine) */
UniValue generateBlocks(std::shared_ptr<CReserveScript> coinbaseScript, int nGenerate, uint64_t nMaxTries, bool keepScript);

/** Check bounds on a command line confirm target */
unsigned int ParseConfirmTarget(const UniValue& value);

UniValue estimatesmartfee(const JSONRPCRequest& request);

#endif
