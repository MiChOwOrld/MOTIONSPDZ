#include "base/party.h"
#include "multiplication_triple/sp_provider.h"
#include "statistics/run_time_statistics.h"
#include "utility/bit_vector.h"
#include "utility/logger.h"

#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <iostream>

using namespace encrypto::motion;

TEST(SpdzTests, DistributeGlobalMacKeyValidation) {
constexpr std::size_t number_of_parties = 2;
std::cout << "Creating " << number_of_parties << " locally connected parties..." << std::endl;

auto parties = MakeLocallyConnectedParties(number_of_parties, /*port=*/14000, /*logging=*/true);
ASSERT_EQ(parties.size(), number_of_parties);

// Turn off auto-online after setup
for (auto& party : parties) {
party->GetConfiguration()->SetOnlineAfterSetup(false);
}

// Καλούμε DistributeGlobalMacKey() σε κάθε party
std::vector<std::thread> sp_threads;
for (std::size_t i = 0; i < parties.size(); ++i) {
sp_threads.emplace_back([i, &parties]() {
auto& sp_provider = dynamic_cast<SpProviderFromOts&>(parties[i]->GetBackend()->GetSpProvider());
sp_provider.DistributeGlobalMacKey();
});
}
for (auto& t : sp_threads) {
t.join();
}

// Εκτελούμε Run() για να κλείσουν τα setup phases
std::vector<std::thread> threads;
for (std::size_t i = 0; i < parties.size(); ++i) {
threads.emplace_back([i, &parties]() {
parties[i]->Run();
});
}
for (auto& t : threads) {
t.join();
}

// Ελέγχουμε ότι το alpha_share_ υπάρχει
std::vector<std::uint64_t> alpha_shares;
for (std::size_t i = 0; i < number_of_parties; ++i) {
auto& sp_provider = dynamic_cast<SpProviderFromOts&>(parties[i]->GetBackend()->GetSpProvider());
alpha_shares.push_back(sp_provider.GetAlphaShare());
std::cout << "Party " << i << " alpha_share = " << alpha_shares.back() << std::endl;
}

// Περαιτέρω έλεγχος: ο party 0 πρέπει να έχει non-zero alpha (παρήγαγε το κλειδί)
EXPECT_NE(alpha_shares[0], 0u);

// Οι υπόλοιποι parties πρέπει να έχουν πάρει σωστό alpha
for (std::size_t i = 1; i < number_of_parties; ++i) {
EXPECT_EQ(alpha_shares[i], alpha_shares[0]);
}
}
