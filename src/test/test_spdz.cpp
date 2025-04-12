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

TEST(SpdzTests, DistributeGlobalMacKeyRuns) {
  constexpr std::size_t number_of_parties = 2;
  std::cout << "Creating " << number_of_parties << " locally connected parties..." << std::endl;

  auto parties = MakeLocallyConnectedParties(number_of_parties, /*port=*/13000, /*logging=*/true);
  std::cout << "parties.size() = " << parties.size() << std::endl;
  std::cout << "Parties created successfully." << std::endl;

  // Turn off auto-online after setup
  for (auto& party : parties) {
    party->GetConfiguration()->SetOnlineAfterSetup(false);
    std::size_t id = party->GetConfiguration()->GetMyId();
    party->GetLogger()->LogDebug(fmt::format("Configured party {} with OnlineAfterSetup=false", id));
  }

  std::cout << "Starting DistributeGlobalMacKey phase..." << std::endl;

  std::vector<std::thread> sp_threads;
  for (std::size_t i = 0; i < parties.size(); ++i) {
    sp_threads.emplace_back([i, &parties]() {
      std::cout << "Registering OT for party " << i << std::endl;
      parties[i]->GetLogger()->LogDebug(fmt::format("Party {}: Starting DistributeGlobalMacKey()", i));
      auto& sp_provider = dynamic_cast<SpProviderFromOts&>(parties[i]->GetBackend()->GetSpProvider());
      sp_provider.DistributeGlobalMacKey();
      parties[i]->GetLogger()->LogDebug(fmt::format("Party {}: Finished DistributeGlobalMacKey()", i));
    });
  }
  for (auto& t : sp_threads) {
    t.join();
  }

  // Εκτέλεση Run() σε threads
  std::vector<std::thread> threads;
  for (std::size_t i = 0; i < parties.size(); ++i) {
    threads.emplace_back([i, &parties]() {
      std::cout << "Party " << i << " calling Run()" << std::endl;
      parties[i]->GetLogger()->LogDebug(fmt::format("Party {}: Starting Run()", i));
      parties[i]->Run();
      parties[i]->GetLogger()->LogDebug(fmt::format("Party {}: Finished Run()", i));
      std::cout << "Party " << i << " finished Run()" << std::endl;
    });
  }

  for (auto& t : threads) {
    t.join();
  }

  // Έλεγχος ότι τα ots_* έχουν γεμίσει σωστά
  auto& sp0 = dynamic_cast<SpProviderFromOts&>(parties[0]->GetBackend()->GetSpProvider());
  auto& sp1 = dynamic_cast<SpProviderFromOts&>(parties[1]->GetBackend()->GetSpProvider());

  EXPECT_EQ(sp0.GetOtsAlphaSender().size(), 1);
  EXPECT_EQ(sp1.GetOtsAlphaReceiver().size(), 1);

  EXPECT_NE(sp0.GetOtsAlphaSender().at(0), nullptr);
  EXPECT_NE(sp1.GetOtsAlphaReceiver().at(0), nullptr);
}
