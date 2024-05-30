// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_MINER_H
#define BITCOIN_INTERFACES_MINER_H

namespace node {
struct CBlockTemplate;
struct NodeContext;
} // namespace node

class CBlockIndex;
class BlockValidationState;
class CBlockIndex;

namespace interfaces {

//! Interface giving clients (RPC, Stratum v2 Template Provider in the future)
//! ability to create block templates.

class Miner
{
public:
    virtual ~Miner() {}

    /** If this chain is exclusively used for testing */
    virtual bool isTestChain() = 0;

    //! Returns the index entry for the tip of this chain, or nullptr if none.
    virtual CBlockIndex* getTip() = 0;

    /** Construct a new block template with coinbase to scriptPubKeyIn */
    virtual std::unique_ptr<node::CBlockTemplate> createNewBlock(const CScript& scriptPubKeyIn) = 0;

    /**
     * Check a block is completely valid from start to finish.
     * Only works on top of our current best block.
     * Does not check proof-of-work.
     * */
    virtual bool testBlockValidity(BlockValidationState& state, const CBlock& block, bool check_merkle_root) = 0;

    //! Get internal node context. Useful for RPC and testing,
    //! but not accessible across processes.
    virtual node::NodeContext* context() { return nullptr; }
};

//! Return implementation of Miner interface.
std::unique_ptr<Miner> MakeMiner(node::NodeContext& node);

} // namespace interfaces

#endif // BITCOIN_INTERFACES_MINER_H
