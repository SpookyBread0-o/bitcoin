// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <util/bitset.h>
#include <cluster_linearize.h>

using namespace cluster_linearize;

namespace {

/** Construct a linear graph. These are pessimal for AncestorCandidateFinder, as they maximize
 *  the number of ancestor set feerate updates. */
template<typename S>
DepGraph<S> MakeLinearGraph(ClusterIndex ntx)
{
    DepGraph<S> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        depgraph.AddTransaction({-int32_t(i), 1});
        if (i > 0) depgraph.AddDependency(i - 1, i);
    }
    return depgraph;
}

// Construct a difficult graph. These need at least sqrt(2^(n-1)) iterations in the best
// implemented algorithms.
template<typename S>
DepGraph<S> MakeHardGraph(ClusterIndex ntx)
{
    DepGraph<S> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        if (ntx & 1) {
            if (i == 0) {
                depgraph.AddTransaction({1, 2});
            } else if (i == 1) {
                depgraph.AddTransaction({14, 2});
                depgraph.AddDependency(0, 1);
            } else if (i == 2) {
                depgraph.AddTransaction({6, 1});
                depgraph.AddDependency(2, 1);
            } else if (i == 3) {
                depgraph.AddTransaction({5, 1});
                depgraph.AddDependency(2, 3);
            } else if ((i & 1) == 0) {
                depgraph.AddTransaction({7, 1});
                depgraph.AddDependency(i - 1, i);
            } else {
                depgraph.AddTransaction({5, 1});
                depgraph.AddDependency(i, 4);
            }
        } else {
            if (i == 0) {
                depgraph.AddTransaction({1, 1});
            } else if (i == 1) {
                depgraph.AddTransaction({3, 1});
                depgraph.AddDependency(0, 1);
            } else if (i == 2) {
                depgraph.AddTransaction({1, 1});
                depgraph.AddDependency(0, 2);
            } else if (i & 1) {
                depgraph.AddTransaction({4, 1});
                depgraph.AddDependency(i - 1, i);
            } else {
                depgraph.AddTransaction({0, 1});
                depgraph.AddDependency(i, 3);
            }
        }
    }
    return depgraph;
}

/** Benchmark that does search-based candidate finding with 10000 iterations. */
template<typename S>
void BenchLinearizePerIterWorstCase(ClusterIndex ntx, benchmark::Bench& bench)
{
    const auto depgraph = MakeHardGraph<S>(ntx);
    const auto iter_limit = std::min<uint64_t>(10000, uint64_t{1} << (ntx / 2 - 1));
    uint64_t rng_seed = 0;
    bench.batch(iter_limit).unit("iters").run([&] {
        uint64_t iters = iter_limit;
        SearchCandidateFinder finder(depgraph, rng_seed++);
        finder.FindCandidateSet(iters, {});
        assert(iters == 0);
    });
}

/** Benchmark for linearization of a trivial linear graph using just ancestor sort. */
template<typename S>
void BenchLinearizeNoItersWorstCase(ClusterIndex ntx, benchmark::Bench& bench)
{
    const auto depgraph = MakeLinearGraph<S>(ntx);
    uint64_t rng_seed = 0;
    bench.run([&] {
        // Do 10 iterations just to make sure some of that logic is executed, but this is
        // effectively negligible.
        uint64_t iters = 10;
        Linearize(depgraph, iters, rng_seed++);
    });
}

} // namespace

static void LinearizePerIter16TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<16>>(16, bench); }
static void LinearizePerIter32TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<32>>(32, bench); }
static void LinearizePerIter48TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<48>>(48, bench); }
static void LinearizePerIter64TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<64>>(64, bench); }
static void LinearizePerIter75TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<75>>(75, bench); }
static void LinearizePerIter99TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<99>>(99, bench); }

static void LinearizeNoIters16TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<16>>(16, bench); }
static void LinearizeNoIters32TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<32>>(32, bench); }
static void LinearizeNoIters48TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<48>>(48, bench); }
static void LinearizeNoIters64TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<64>>(64, bench); }
static void LinearizeNoIters75TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<75>>(75, bench); }
static void LinearizeNoIters99TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<99>>(99, bench); }

BENCHMARK(LinearizePerIter16TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter32TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter48TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter64TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter75TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter99TxWorstCase, benchmark::PriorityLevel::HIGH);

BENCHMARK(LinearizeNoIters16TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters32TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters48TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters64TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters75TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters99TxWorstCase, benchmark::PriorityLevel::HIGH);
