// Copyright (c) 2022 The Pocketcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <key.h>
#include <txmempool.h>
#include <validation.h>
#include <random.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <core_io.h>
#include <policy/policy.h>
#include "pocketdb/web/PocketRpc.h"
#include "pocketdb/services/Serializer.h"
#include "pocketdb/pocketnet.h"
#include "pocketdb/repositories/web/WebRpcRepository.h"
#include "pocketdb/SQLiteConnection.h"
#include "websocket/notifyprocessor.h"

#include <boost/test/unit_test.hpp>


namespace pocketnet_delayed_post_tests {
struct PocketNetTestingSetup : public TestChain100Setup {
    unordered_map<std::string, CKey> keyMap;
    int tx_index;
    bool ToMemPool(const CMutableTransaction& tx, const PTransactionRef ptx);
    std::string GetAccountAddress(std::string name);
    CTransactionRef SendCoins(std::string name);
    CTransactionRef CreateAccount(std::string name, CTransactionRef txIn);
    CTransactionRef CreateDelayPost(std::string name, CTransactionRef txIn, int blockHeight);};
}


BOOST_FIXTURE_TEST_SUITE(pocketnet_delayed_post_tests, PocketNetTestingSetup)

const UniValue NullUniValue;

std::string PocketNetTestingSetup::GetAccountAddress(std::string name)
{
    CPubKey pubkey = keyMap[name].GetPubKey();
    CTxDestination dest = GetDestinationForKey(pubkey, OutputType::LEGACY);
    return EncodeDestination(dest);
}

bool PocketNetTestingSetup::ToMemPool(const CMutableTransaction& tx, const PTransactionRef ptx)
{
    LOCK(cs_main);
    LOCK(m_node.mempool->cs);

    TxValidationState state;
    return AcceptToMemoryPool(*m_node.mempool, state, MakeTransactionRef(tx), ptx,
        nullptr /* plTxnReplaced */, false /* bypass_limits */);
};


CTransactionRef PocketNetTestingSetup::CreateDelayPost(std::string name, CTransactionRef txIn, int blockHeight)
{
    unsigned char* opData = (unsigned char*) "share";
    std::vector<unsigned char> op(opData, opData + sizeof("share") - 1);

    unsigned int flags = SCRIPT_VERIFY_STRICTENC;
    CAmount amount = 0;
    ScriptError err;

    UniValue pocketData;
    pocketData.setObject();
    pocketData.pushKV("l", "en");
    pocketData.pushKV("c", name + " caption");
    pocketData.pushKV("m", name + " post message");
    pocketData.pushKV("u", name + ".com");
    pocketData.pushKV("s", name + "settings");
    pocketData.pushKV("t", "[\"tag1\",\"tag2\"]");
    pocketData.pushKV("i", name + " images");
	shared_ptr<Transaction> _ptx = PocketHelpers::TransactionHelper::CreateInstance(PocketTx::CONTENT_POST);
    _ptx->SetHash("");
    _ptx->DeserializeRpc(pocketData);

    // Create a CONTENT_POST transaction
    CMutableTransaction mTx;
    mTx.nVersion = 1;
    mTx.vin.resize(1);
    // Create a transaction with input from earlier block
    mTx.vin[0].prevout.hash = txIn->GetHash();
    mTx.vin[0].prevout.n = 1;
    mTx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    mTx.vout.resize(2);

    // Lock until block
    mTx.nLockTime = blockHeight;
    mTx.nVersion = 2;
    mTx.vout[0].nValue = 0;
    mTx.vout[0].scriptPubKey = CScript() << OP_RETURN << op << ParseHex(_ptx->BuildHash());
    amount = 8*CENT;
    mTx.vout[1].nValue = amount;
    mTx.vout[1].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyMap[name].GetPubKey().GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;

    // Sign:
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(txIn->vout[1].scriptPubKey, mTx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    BOOST_CHECK(keyMap[name].Sign(hash, vchSig));
    vchSig.push_back((unsigned char)SIGHASH_ALL);
    mTx.vin[0].scriptSig << vchSig << ToByteVector(keyMap[name].GetPubKey());

    BOOST_CHECK(VerifyScript(mTx.vin[0].scriptSig, txIn->vout[1].scriptPubKey, nullptr, flags, MutableTransactionSignatureChecker(&mTx, 0, amount), &err));

    const auto tx = MakeTransactionRef(mTx);
    
    // Deserialize incoming data
    auto[deserializeOk, ptx] = PocketServices::Serializer::DeserializeTransactionRpc(tx, pocketData);
    if (!deserializeOk)
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX deserialize failed");

    ptx->SetAddress(GetAccountAddress(name));

    // Insert into mempool
    BOOST_CHECK(ToMemPool(mTx, ptx));

    return tx;
}


CTransactionRef PocketNetTestingSetup::CreateAccount(std::string name, CTransactionRef txIn)
{
    unsigned char* opData = (unsigned char*) "userInfo";
    std::vector<unsigned char> op(opData, opData + sizeof("userInfo") - 1);

    unsigned int flags = SCRIPT_VERIFY_STRICTENC;
    CAmount amount = 0;
    ScriptError err;

    UniValue pocketData;
    pocketData.setObject();
    pocketData.pushKV("r", keyMap[name].GetPubKey().GetID().ToString());
    pocketData.pushKV("l", "en");
    pocketData.pushKV("n", name.c_str());
    pocketData.pushKV("a", name + " avatar");
    pocketData.pushKV("s", name + ".com");
    pocketData.pushKV("k", HexStr(GetScriptForRawPubKey(coinbaseKey.GetPubKey())).c_str());
    pocketData.pushKV("b", name + " donations");
	shared_ptr<Transaction> _ptx = PocketHelpers::TransactionHelper::CreateInstance(PocketTx::ACCOUNT_USER);
    _ptx->SetHash("");
    _ptx->DeserializeRpc(pocketData);

    // Create a ACCOUNT_USER transaction
    CMutableTransaction mTx;
    mTx.nVersion = 1;
    mTx.vin.resize(1);
    // Create a transaction with input from earlier block
    mTx.vin[0].prevout.hash = txIn->GetHash();
    mTx.vin[0].prevout.n = 0;
    mTx.vout.resize(2);
    mTx.vout[0].nValue = 0;
    mTx.vout[0].scriptPubKey = CScript() << OP_RETURN << op << ParseHex(_ptx->BuildHash());
    amount = 9*CENT;
    mTx.vout[1].nValue = amount;
    mTx.vout[1].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyMap[name].GetPubKey().GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;

    // Sign:
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(txIn->vout[0].scriptPubKey, mTx, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    BOOST_CHECK(keyMap[name].Sign(hash, vchSig));
    vchSig.push_back((unsigned char)SIGHASH_ALL);
    mTx.vin[0].scriptSig << vchSig << ToByteVector(keyMap[name].GetPubKey());

    BOOST_CHECK(VerifyScript(mTx.vin[0].scriptSig, txIn->vout[0].scriptPubKey, nullptr, flags, MutableTransactionSignatureChecker(&mTx, 0, amount), &err));

    const auto tx = MakeTransactionRef(mTx);

    // Deserialize incoming data
    auto[deserializeOk, ptx] = PocketServices::Serializer::DeserializeTransactionRpc(tx, pocketData);
    if (!deserializeOk)
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX deserialize failed");
 
    ptx->SetAddress(GetAccountAddress(name));

    // Insert into mempool
    BOOST_CHECK(ToMemPool(mTx, ptx));

    return tx;
}

// Send coins from the coinbase account to a new user account
CTransactionRef PocketNetTestingSetup::SendCoins(std::string name)
{
    CKey userKey;
    ScriptError err;
    CAmount amount = 0;
    unsigned int flags = SCRIPT_VERIFY_STRICTENC;

    userKey.MakeNewKey(true);
    keyMap[name] = userKey;

    CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyMap[name].GetPubKey().GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;

    // Send coinbase coins to new account
    CMutableTransaction mTx;
    mTx.nVersion = 1;
    mTx.vin.resize(1);
    // Create a transaction with input from earlier block
    mTx.vin[0].scriptWitness = CScriptWitness();
    mTx.vin[0].prevout.hash = m_coinbase_txns[tx_index]->GetHash();
    mTx.vin[0].prevout.n = 0;
    mTx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mTx.vout.resize(1);
    amount = 10*CENT;
    mTx.vout[0].nValue = amount;
    mTx.vout[0].scriptPubKey = scriptPubKey;

    // Sign:
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(m_coinbase_txns[tx_index]->vout[0].scriptPubKey, mTx, 0, SIGHASH_ALL, amount, SigVersion::BASE);
    BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
    vchSig.push_back((unsigned char)SIGHASH_ALL);
    mTx.vin[0].scriptSig << vchSig;

    BOOST_CHECK(VerifyScript(mTx.vin[0].scriptSig, m_coinbase_txns[tx_index]->vout[0].scriptPubKey, nullptr, flags, MutableTransactionSignatureChecker(&mTx, 0, amount), &err));

    CTransactionRef tx = MakeTransactionRef(mTx);

    auto[ok, pocketTx] = PocketServices::Serializer::DeserializeTransaction(tx);
    BOOST_CHECK(ok);

    tx_index++;

    BOOST_CHECK(ToMemPool(mTx, pocketTx));

    return tx;
}

BOOST_AUTO_TEST_CASE(pocketnet_delay_posts)
{
    std::vector<CMutableTransaction> noTxns;
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    BlockValidationState state;
    auto sqlConnection = std::make_shared<PocketDb::SQLiteConnection>();

    tx_index = 0;

    // Create 2 blocks with no transactions to get us to the correct spend height
    // 100 block coinbase maturity is required before we spend coins
    CBlock block = CreateAndProcessBlock(noTxns, scriptPubKey);
    BOOST_CHECK(ActivateBestChain(state, Params()));
    block = CreateAndProcessBlock(noTxns, scriptPubKey);
    BOOST_CHECK(ActivateBestChain(state, Params()));

    // Send some coins to Alice to create new acocunt 
    CTransactionRef aliceTx = SendCoins("alice");

    // Create a new block and make sure both Bob and Alice's transactions are present
    block = CreateAndProcessMempoolBlock(*m_node.mempool, scriptPubKey);
    BOOST_CHECK(block.vtx.size() == 2);
    BOOST_CHECK(ActivateBestChain(state, Params()));
    BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() == block.GetHash());

    // Create some empty blocks to ensure coin maturity
    block = CreateAndProcessBlock(noTxns, scriptPubKey);
    BOOST_CHECK(ActivateBestChain(state, Params()));
    block = CreateAndProcessBlock(noTxns, scriptPubKey);
    BOOST_CHECK(ActivateBestChain(state, Params()));
    block = CreateAndProcessBlock(noTxns, scriptPubKey);
    BOOST_CHECK(ActivateBestChain(state, Params()));
    block = CreateAndProcessBlock(noTxns, scriptPubKey);
    BOOST_CHECK(ActivateBestChain(state, Params()));

    // Create new account for Alice
    aliceTx = CreateAccount("alice", aliceTx);
 
    block = CreateAndProcessMempoolBlock(*m_node.mempool, scriptPubKey);
    BOOST_CHECK(block.vtx.size() == 2);
    BOOST_CHECK(ActivateBestChain(state, Params()));
    BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() == block.GetHash());

    // Create post after block 110
    aliceTx = CreateDelayPost("alice", aliceTx, 110);
 
    // block 109, verify transaction is not accepted
    block = CreateAndProcessMempoolBlock(*m_node.mempool, scriptPubKey);
    BOOST_CHECK(block.vtx.size() == 1);
    BOOST_CHECK(ActivateBestChain(state, Params()));
    BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() == block.GetHash());

    // block 110, verify transaction is not accepted
    block = CreateAndProcessMempoolBlock(*m_node.mempool, scriptPubKey);
    BOOST_CHECK(block.vtx.size() == 1);
    BOOST_CHECK(ActivateBestChain(state, Params()));
    BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() == block.GetHash());

    // block 111, now block will be accepted into block
    block = CreateAndProcessMempoolBlock(*m_node.mempool, scriptPubKey);
    BOOST_CHECK(block.vtx.size() == 2);
    BOOST_CHECK(ActivateBestChain(state, Params()));
    BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() == block.GetHash());


    // cleanup
    keyMap.erase("alice");
}


BOOST_AUTO_TEST_SUITE_END()