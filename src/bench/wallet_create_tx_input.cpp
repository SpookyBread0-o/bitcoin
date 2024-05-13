// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <chainparams.h>
#include <wallet/coincontrol.h>
#include <consensus/merkle.h>
#include <kernel/chain.h>
#include <node/context.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

using wallet::CWallet;
using wallet::CreateMockableWalletDatabase;
using wallet::WALLET_FLAG_DESCRIPTORS;

std::tuple<CScript, std::vector<wallet::CRecipient>> SetupBenchmark() {
    auto test_setup = MakeNoLogFileContext<const TestingSetup>();
    CWallet wallet{test_setup->m_node.chain.get(), "", CreateMockableWalletDatabase()};
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }
    auto dest = getNewDestination(wallet, OutputType::BECH32);
    auto scriptPubKey = GetScriptForDestination(dest);
    std::vector<wallet::CRecipient> vecSend(100, {dest, 1 * COIN, false});
    return std::make_tuple(scriptPubKey, vecSend);
}

static void BenchmarkAddOutputsPushBack(benchmark::Bench& bench)
{
    auto [scriptPubKey, vecSend] = SetupBenchmark();

    bench.run([&] {
        std::vector<CTxOut> vout;
        for (auto& recipient : vecSend)
        {
            CTxOut txout(recipient.nAmount, scriptPubKey);
            vout.push_back(txout);
            ankerl::nanobench::doNotOptimizeAway(txout);
        }
    });
}

static void BenchmarkAddOutputsPushBackReserve(benchmark::Bench& bench)
{
    auto [scriptPubKey, vecSend] = SetupBenchmark();

    bench.run([&] {
        std::vector<CTxOut> vout;
        vout.reserve(vecSend.size() + 1);
        for (auto& recipient : vecSend)
        {
            CTxOut txout(recipient.nAmount, scriptPubKey);
            vout.push_back(txout);
            ankerl::nanobench::doNotOptimizeAway(txout);
        }
    });
}

static void BenchmarkAddOutputsPushBackMoveReserve(benchmark::Bench& bench)
{
    auto [scriptPubKey, vecSend] = SetupBenchmark();

    bench.run([&] {
        std::vector<CTxOut> vout;
        vout.reserve(vecSend.size() + 1);
        for (auto& recipient : vecSend)
        {
            CTxOut txout(recipient.nAmount, scriptPubKey);
            vout.push_back(std::move(txout));
            ankerl::nanobench::doNotOptimizeAway(txout);
        }
    });
}

static void BenchmarkAddOutputsEmplaceBackReserve(benchmark::Bench& bench)
{
    auto [scriptPubKey, vecSend] = SetupBenchmark();

    bench.run([&] {
        std::vector<CTxOut> vout;
        vout.reserve(vecSend.size() + 1);
        for (auto& recipient : vecSend)
        {
            CTxOut txout(recipient.nAmount, scriptPubKey);
            vout.emplace_back(txout);
            ankerl::nanobench::doNotOptimizeAway(txout);
        }
    });
}

static void BenchmarkAddOutputsInPlaceEmplaceBackReserve(benchmark::Bench& bench)
{
    auto [scriptPubKey, vecSend] = SetupBenchmark();

    bench.run([&] {
        std::vector<CTxOut> vout;
        vout.reserve(vecSend.size() + 1);
        for (auto& recipient : vecSend)
        {
            auto& txout = vout.emplace_back(recipient.nAmount, scriptPubKey);
            ankerl::nanobench::doNotOptimizeAway(txout);
        }
    });
}

BENCHMARK(BenchmarkAddOutputsPushBack, benchmark::PriorityLevel::LOW);
BENCHMARK(BenchmarkAddOutputsPushBackReserve, benchmark::PriorityLevel::LOW);
BENCHMARK(BenchmarkAddOutputsPushBackMoveReserve, benchmark::PriorityLevel::LOW);
BENCHMARK(BenchmarkAddOutputsEmplaceBackReserve, benchmark::PriorityLevel::LOW);
BENCHMARK(BenchmarkAddOutputsInPlaceEmplaceBackReserve, benchmark::PriorityLevel::LOW);
