// Copyright (c) 2022 The Pocketcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <key.h>
#include <validation.h>
#include <miner.h>
#include <pubkey.h>
#include <txmempool.h>
#include <random.h>
#include <script/standard.h>
#include <script/sign.h>
#include <test/test_pocketcoin.h>
#include <utiltime.h>
#include <core_io.h>
#include <keystore.h>
#include <policy/policy.h>
#include "pocketdb/services/Serializer.h"
#include <consensus/merkle.h>

#include <boost/test/unit_test.hpp>


static bool
ToMemPool(const CMutableTransaction& tx)
{
    LOCK(cs_main);

    auto transaction = new CTransaction(tx);
    CTransactionRef txref(transaction);

    auto[ok, pocketTx] = PocketServices::Serializer::DeserializeTransaction(txref);
    BOOST_CHECK(ok);

    CValidationState state;
    return AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), 
                              pocketTx /* pocketTx */,
                              nullptr /* pfMissingInputs */,
                              nullptr /* plTxnReplaced */,
                              true /* bypass_limits */,
                              0 /* nAbsurdFee */,
                              false /* test_accept */);
}

static std::shared_ptr<CBlock> StakeBlock(const CScript& coinbase_scriptPubKey)
{
    auto block = std::make_shared<CBlock>(
        BlockAssembler{Params()}
            .CreateNewBlock(coinbase_scriptPubKey, /* fMineWitnessTx */ true, /*fProofOfStake */ true)
            ->block);

    block->nTime = ::chainActive.Tip()->GetMedianTimePast() + 1;
    block->hashMerkleRoot = BlockMerkleRoot(*block);

    return block;
}

static UniValue verifydb()
{
    UniValue result(UniValue::VARR);
    uint256 tx_hash;
    uint256 block_hash;
    CTransactionRef tx = nullptr;

    LOCK(cs_main);
    LOCK(mempool.cs);
    auto hashes = PocketDb::ChainRepoInst.GetTransactionHashes();

    for (auto &hash : hashes)
    {
        // Make sure each transaction exists in either the blockchain or the mempool
        tx_hash = uint256S(hash);
        if (!GetTransaction(tx_hash, tx, Params().GetConsensus(), block_hash, true))
        {
            std::cout << "Orphan transaction hash = " <<  hash << " block = " << block_hash.ToString() << "\n";
            result.push_back(tx_hash.ToString());
        }
    }

    return result;
}

BOOST_AUTO_TEST_SUITE(pocketnet_block_tests)

BOOST_FIXTURE_TEST_CASE(pocketnet_block_rollback, TestChain100Setup)
{
	const std::vector<unsigned char> op_true{OP_TRUE};
    uint256 witness_program;
    CSHA256().Write(&op_true[0], op_true.size()).Finalize(witness_program.begin());

    const CScript SCRIPT_PUB{CScript(OP_0) << std::vector<unsigned char>{witness_program.begin(), witness_program.end()}};

    const CChainParams& chainparams = Params();
    CValidationState state;
    int64_t disconnectHeight = 98;
	bool ret = true;

	BOOST_CHECK(InvalidateBlock(state, chainparams, chainActive.Tip()) );

    UniValue result = verifydb();
	BOOST_CHECK(result[0].get_str() == std::string("aced9fcaba8f66be3d4d51a95cb048dda6611b8f2d2bf4541d9e2e16c07ee1c9"));

    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    // Create 2block with no transactions to get us to the correct spend height, 100 block coinbase maturity is required before we spend coins
    std::vector<CMutableTransaction> noTxns;

    CBlock block = CreateAndProcessBlock(noTxns, scriptPubKey);
    BOOST_CHECK(ActivateBestChain(state, Params()));

    block = CreateAndProcessBlock(noTxns, scriptPubKey);
    BOOST_CHECK(ActivateBestChain(state, Params()));

    std::vector<CMutableTransaction> spends;
	int txcount = 2;
    spends.resize(txcount);
    for (int i = 0; i < txcount; i++)
	{
        spends[i].nVersion = 1;
        spends[i].vin.resize(1);
        // Create a transaction with input from earlier block
        spends[i].vin[0].prevout.hash = m_coinbase_txns[i]->GetHash();
        spends[i].vin[0].prevout.n = 0;
        spends[i].vout.resize(1);
        spends[i].vout[0].nValue = 11*CENT;
        spends[i].vout[0].scriptPubKey = scriptPubKey;

        // Sign:
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(scriptPubKey, spends[i], 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spends[i].vin[0].scriptSig << vchSig;
    }
    // Test 1: make sure this block is accepted.
    block = CreateAndProcessBlock(spends, scriptPubKey);

    result = verifydb();
	BOOST_CHECK(result[0].get_str() == std::string("aced9fcaba8f66be3d4d51a95cb048dda6611b8f2d2bf4541d9e2e16c07ee1c9"));

    BOOST_CHECK(ActivateBestChain(state, Params()));
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());

    result = verifydb();
	BOOST_CHECK(result[0].get_str() == std::string("aced9fcaba8f66be3d4d51a95cb048dda6611b8f2d2bf4541d9e2e16c07ee1c9"));

	BOOST_CHECK(CVerifyDB().VerifyDB(Params(), pcoinsTip.get(), 4, 102));


    // Generate 4 new blocks so we can spend earlier transactions with 100 block coinbase maturity
    CreateAndProcessBlock(noTxns, scriptPubKey);
    CreateAndProcessBlock(noTxns, scriptPubKey);
    CreateAndProcessBlock(noTxns, scriptPubKey);
    block = CreateAndProcessBlock(noTxns, scriptPubKey);
	BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());


	// Add transaction to mempool, verify it's in Transactions database

    std::vector<CMutableTransaction> spends1;
	txcount = 2;
    spends1.resize(txcount);
    for (int i = 0; i < txcount; i++)
	{
        spends1[i].nVersion = 1;
        spends1[i].vin.resize(1);
        // Create a transaction with input from earlier block
        spends1[i].vin[0].prevout.hash = m_coinbase_txns[i+2]->GetHash();
        spends1[i].vin[0].prevout.n = 0;
        spends1[i].vout.resize(1);
        spends1[i].vout[0].nValue = 11*CENT;
        spends1[i].vout[0].scriptPubKey = scriptPubKey;

        // Sign:
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(scriptPubKey, spends1[i], 0, SIGHASH_ALL, 0, SigVersion::BASE);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spends1[i].vin[0].scriptSig << vchSig;
    }

    BOOST_CHECK(ToMemPool(spends1[0]));
    BOOST_CHECK(ToMemPool(spends1[1]));

	cout << "spends1[0] tx hash = " << spends1[0].GetHash().GetHex() << " vin = " << spends1[0].vin[0].prevout.hash.GetHex() << "\n";
	cout << "spends1[1] tx hash = " << spends1[1].GetHash().GetHex() << " vin = " << spends1[1].vin[0].prevout.hash.GetHex() << "\n";
	result = verifydb();
	BOOST_CHECK(result[0].get_str() == std::string("aced9fcaba8f66be3d4d51a95cb048dda6611b8f2d2bf4541d9e2e16c07ee1c9"));

    block = CreateAndProcessBlock(noTxns, scriptPubKey);
	BOOST_CHECK(ActivateBestChain(state, Params()));
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());

	result = verifydb();
	BOOST_CHECK(result.size() == 1 || result[0].get_str() == std::string("aced9fcaba8f66be3d4d51a95cb048dda6611b8f2d2bf4541d9e2e16c07ee1c9"));

	// Eject from mempool, verify Transaction database again

	// Add transaction to mempool, then accept it into block, verify db

	// Rollback block

	// Add block with transactions, then second block which takes inputs from previous, then rollback

	// expire mempool
}

BOOST_AUTO_TEST_SUITE_END()
