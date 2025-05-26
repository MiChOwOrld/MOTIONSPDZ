#include "base/party.h"
#include "base/backend.h"
#include "protocols/constant/constant_wire.h"
#include "protocols/share_wrapper.h"
#include "multiplication_triple/sp_provider.h"
#include "multiplication_triple/mt_provider.h"
#include "statistics/run_time_statistics.h"
#include "utility/bit_vector.h"
#include "utility/logger.h"

#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <iostream>

using namespace encrypto::motion;

// ------------------------------------------------------------
// Test 1: Basic DistributeGlobalMacKey Execution
// ------------------------------------------------------------
TEST(SpdzTests, DistributeGlobalMacKeyRuns) {
  constexpr std::size_t number_of_parties = 2;
  std::cout << "\n[TEST 1] Creating " << number_of_parties << " locally connected parties..." << std::endl;

  auto parties = MakeLocallyConnectedParties(number_of_parties, /*port=*/13000, /*logging=*/true);
  ASSERT_EQ(parties.size(), number_of_parties);
  std::cout << "[INFO] Parties created successfully." << std::endl;

  for (auto& party : parties) {
    party->GetConfiguration()->SetOnlineAfterSetup(false);
    std::size_t id = party->GetConfiguration()->GetMyId();
    party->GetLogger()->LogDebug(fmt::format("Configured party {} with OnlineAfterSetup=false", id));
    std::cout << "[DEBUG] Configured party " << id << " with OnlineAfterSetup=false." << std::endl;
  }

  std::cout << "[INFO] Starting DistributeGlobalMacKey phase..." << std::endl;
  std::vector<std::thread> sp_threads;
  for (std::size_t i = 0; i < parties.size(); ++i) {
    sp_threads.emplace_back([i, &parties]() {
      std::cout << "[THREAD] Party " << i << ": Starting CommunicationLayer..." << std::endl;
      parties[i]->GetBackend()->GetCommunicationLayer().Start();
      std::cout << "[THREAD] Party " << i << ": Registering OT and calling DistributeGlobalMacKey()" << std::endl;
      parties[i]->GetLogger()->LogDebug(fmt::format("Party {}: Starting DistributeGlobalMacKey()", i));
      auto& sp_provider = dynamic_cast<SpProviderFromOts&>(parties[i]->GetBackend()->GetSpProvider());
      sp_provider.DistributeGlobalMacKey();
      parties[i]->GetLogger()->LogDebug(fmt::format("Party {}: Finished DistributeGlobalMacKey()", i));
      std::cout << "[THREAD] Party " << i << ": Finished DistributeGlobalMacKey()" << std::endl;
    });
  }
  for (auto& t : sp_threads) {
    t.join();
  }

  std::cout << "[INFO] All parties completed DistributeGlobalMacKey phase." << std::endl;

  std::cout << "[INFO] Starting Run() for all parties..." << std::endl;
  std::vector<std::thread> threads;
  for (std::size_t i = 0; i < parties.size(); ++i) {
    threads.emplace_back([i, &parties]() {
      std::cout << "[THREAD] Party " << i << ": Calling Run()" << std::endl;
      parties[i]->Run();
      std::cout << "[MAIN] Party " << i << ": Run() done." << std::endl;

      std::cout << "[MAIN] Party " << i << ": Calling Finish()..." << std::endl;
      parties[i]->Finish();
      std::cout << "[THREAD] Party " << i << ": Finished Run()" << std::endl;
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::cout << "[INFO] All parties completed Run() phase." << std::endl;

  // Έλεγχος ότι τα ots_* έχουν γεμίσει σωστά
  std::cout << "[INFO] Checking OTs initialization..." << std::endl;
  auto& sp0 = dynamic_cast<SpProviderFromOts&>(parties[0]->GetBackend()->GetSpProvider());
  auto& sp1 = dynamic_cast<SpProviderFromOts&>(parties[1]->GetBackend()->GetSpProvider());

  EXPECT_EQ(sp0.GetOtsAlphaSender().size(), 1);
  EXPECT_EQ(sp1.GetOtsAlphaReceiver().size(), 1);
  EXPECT_NE(sp0.GetOtsAlphaSender().at(0), nullptr);
  EXPECT_NE(sp1.GetOtsAlphaReceiver().at(0), nullptr);

  std::cout << "[SUCCESS] DistributeGlobalMacKey basic run test passed." << std::endl;
}

// ------------------------------------------------------------
// Test 2: Validation of alpha_shares consistency
// ------------------------------------------------------------
TEST(SpdzTests, DistributeGlobalMacKeyValidation) {
  constexpr std::size_t number_of_parties = 2;
  std::cout << "\n[TEST 2] Creating " << number_of_parties << " locally connected parties..." << std::endl;

  auto parties = MakeLocallyConnectedParties(number_of_parties, /*port=*/14000, /*logging=*/true);
  ASSERT_EQ(parties.size(), number_of_parties);
  std::cout << "[INFO] Parties created successfully." << std::endl;

  for (auto& party : parties) {
    party->GetConfiguration()->SetOnlineAfterSetup(false);
    std::size_t id = party->GetConfiguration()->GetMyId();
    std::cout << "[DEBUG] Configured party " << id << " with OnlineAfterSetup=false." << std::endl;
  }

  std::cout << "[INFO] Starting DistributeGlobalMacKey phase..." << std::endl;
  std::vector<std::thread> sp_threads;
  for (std::size_t i = 0; i < parties.size(); ++i) {
    sp_threads.emplace_back([i, &parties]() {
      std::cout << "[THREAD] Party " << i << ": Calling DistributeGlobalMacKey()" << std::endl;
      auto& sp_provider = dynamic_cast<SpProviderFromOts&>(parties[i]->GetBackend()->GetSpProvider());
      sp_provider.DistributeGlobalMacKey();
      std::cout << "[THREAD] Party " << i << ": Finished DistributeGlobalMacKey()" << std::endl;
    });
  }
  for (auto& t : sp_threads) {
    t.join();
  }

  std::cout << "[INFO] All parties completed DistributeGlobalMacKey." << std::endl;

  std::cout << "[INFO] Starting Run() for all parties..." << std::endl;
  std::vector<std::thread> threads;
  for (std::size_t i = 0; i < parties.size(); ++i) {
    threads.emplace_back([i, &parties]() {
      std::cout << "[THREAD] Party " << i << ": Calling Run()" << std::endl;
      parties[i]->Run();
      parties[i]->Finish();
      std::cout << "[THREAD] Party " << i << ": Finished Run()" << std::endl;
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::cout << "[INFO] Collecting alpha_shares from all parties..." << std::endl;
  std::vector<std::uint64_t> alpha_shares;
  for (std::size_t i = 0; i < number_of_parties; ++i) {
    auto& sp_provider = dynamic_cast<SpProviderFromOts&>(parties[i]->GetBackend()->GetSpProvider());
    auto alpha = sp_provider.GetAlphaShare();
    alpha_shares.push_back(alpha);
    std::cout << "[RESULT] Party " << i << " has alpha_share = " << alpha << std::endl;
  }

  // Validation: Ο Party 0 πρέπει να έχει μη μηδενικό alpha
  std::cout << "[INFO] Verifying alpha_shares consistency..." << std::endl;
  EXPECT_NE(alpha_shares[0], 0u) << "[ERROR] Party 0 alpha_share is zero!";
  for (std::size_t i = 1; i < number_of_parties; ++i) {
    EXPECT_EQ(alpha_shares[i], alpha_shares[0]) << "[ERROR] Mismatch in alpha_share for party " << i;
  }

  std::cout << "[SUCCESS] Alpha shares validated successfully!" << std::endl;
}
// ------------------------------------------------------------
// Test 3: Generate Random Triples With MACs and Validate them
// ------------------------------------------------------------
TEST(SpdzTests, GenerateTriplesWithMacsValidation) {
  constexpr std::size_t number_of_triples = 10;
  constexpr std::uint64_t alpha = 123456789;  // Fixed alpha for reproducibility
  std::cout << "\n[TEST 3] Generating " << number_of_triples << " triples with alpha = " << alpha << "..." << std::endl;

  IntegerMtVector<std::uint64_t> triples;
  GenerateRandomTriplesWithMacs(triples, number_of_triples, alpha);

  std::cout << "[INFO] Triples generated. Validating..." << std::endl;

  ASSERT_EQ(triples.a.size(), number_of_triples);
  ASSERT_EQ(triples.b.size(), number_of_triples);
  ASSERT_EQ(triples.c.size(), number_of_triples);
  ASSERT_EQ(triples.mac_a.size(), number_of_triples);
  ASSERT_EQ(triples.mac_b.size(), number_of_triples);
  ASSERT_EQ(triples.mac_c.size(), number_of_triples);

  for (std::size_t i = 0; i < number_of_triples; ++i) {
    std::cout << "[TRIPLE " << i << "] a = " << triples.a[i]
              << ", b = " << triples.b[i]
              << ", c = " << triples.c[i]
              << ", mac_a = " << triples.mac_a[i]
              << ", mac_b = " << triples.mac_b[i]
              << ", mac_c = " << triples.mac_c[i] << std::endl;

    // Ελέγχουμε ότι c = a * b
    EXPECT_EQ(triples.c[i], triples.a[i] * triples.b[i])
      << "[ERROR] Invalid multiplication at triple " << i;

    // Ελέγχουμε ότι τα MACs είναι σωστά
    EXPECT_EQ(triples.mac_a[i], alpha * triples.a[i])
      << "[ERROR] Invalid mac_a at triple " << i;
    EXPECT_EQ(triples.mac_b[i], alpha * triples.b[i])
      << "[ERROR] Invalid mac_b at triple " << i;
    EXPECT_EQ(triples.mac_c[i], alpha * triples.c[i])
      << "[ERROR] Invalid mac_c at triple " << i;
  }

  std::cout << "[SUCCESS] All triples and MACs validated successfully!" << std::endl;
}
// ------------------------------------------------------------
// Test 4: Full SPDZ Preprocessing Phase (Integration Test)
// ------------------------------------------------------------
TEST(SpdzTests, FullPreprocessingIntegrationTest) {
  constexpr std::size_t number_of_parties = 2;
  constexpr std::size_t number_of_triples = 5;
  std::cout << "\n[TEST 4] Starting full preprocessing integration test..." << std::endl;

  // Create locally connected parties
  auto parties = MakeLocallyConnectedParties(number_of_parties, /*port=*/15000, /*logging=*/true);
  ASSERT_EQ(parties.size(), number_of_parties);

  for (auto& party : parties) {
    party->GetConfiguration()->SetOnlineAfterSetup(false);
  }

  // Distribute Global MAC Key
  std::cout << "[INFO] Distributing Global MAC key among parties..." << std::endl;
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

  std::cout << "[INFO] Running parties (setup phase)..." << std::endl;
  std::vector<std::thread> threads;
  for (std::size_t i = 0; i < parties.size(); ++i) {
    threads.emplace_back([i, &parties]() {
      parties[i]->Run();
      parties[i]->Finish();
    });
  }
  for (auto& t : threads) {
    t.join();
  }

  std::cout << "[INFO] All parties completed Run(). Proceeding to triple generation..." << std::endl;

  // Each party generates triples using its alpha_share
  for (std::size_t i = 0; i < number_of_parties; ++i) {
    std::cout << "\n[PARTY " << i << "] Generating " << number_of_triples << " triples..." << std::endl;
    auto& sp_provider = dynamic_cast<SpProviderFromOts&>(parties[i]->GetBackend()->GetSpProvider());
    auto alpha = sp_provider.GetAlphaShare();

    IntegerMtVector<std::uint64_t> triples;
    GenerateRandomTriplesWithMacs(triples, number_of_triples, alpha);

    for (std::size_t j = 0; j < number_of_triples; ++j) {
      std::cout << "[TRIPLE " << j << "] a = " << triples.a[j]
                << ", b = " << triples.b[j]
                << ", c = " << triples.c[j]
                << ", mac_a = " << triples.mac_a[j]
                << ", mac_b = " << triples.mac_b[j]
                << ", mac_c = " << triples.mac_c[j] << std::endl;

      // Έλεγχος ότι c = a * b
      EXPECT_EQ(triples.c[j], triples.a[j] * triples.b[j])
        << "[ERROR] Triple multiplication invalid at triple " << j;

      // Έλεγχος ότι τα MACs είναι σωστά
      EXPECT_EQ(triples.mac_a[j], alpha * triples.a[j])
        << "[ERROR] Invalid mac_a at triple " << j;
      EXPECT_EQ(triples.mac_b[j], alpha * triples.b[j])
        << "[ERROR] Invalid mac_b at triple " << j;
      EXPECT_EQ(triples.mac_c[j], alpha * triples.c[j])
        << "[ERROR] Invalid mac_c at triple " << j;
    }
    std::cout << "[SUCCESS] Party " << i << " validated all triples and MACs successfully!" << std::endl;
  }

  std::cout << "\n[SUCCESS] Full SPDZ Preprocessing Integration Test Completed!" << std::endl;
}
// ------------------------------------------------------------
// Test 5: InputShareWithMac Validation (Input & MAC correctness)
// ------------------------------------------------------------
TEST(SpdzTests, InputShareWithMacValidation) {
  constexpr std::size_t number_of_parties = 2;
  constexpr std::uint64_t input_value = 12345;
  constexpr std::size_t input_owner = 0;
  constexpr std::size_t bit_length = 64;

  std::cout << "\n[TEST 5 - DEBUG] Starting InputShareWithMac validation test..." << std::endl << std::flush;

  auto parties = MakeLocallyConnectedParties(number_of_parties, /*port=*/16000, /*logging=*/true);
  ASSERT_EQ(parties.size(), number_of_parties);
  std::cout << "[INFO] Created and connected " << number_of_parties << " parties.\n" << std::flush;

  for (auto& party : parties) {
    party->GetConfiguration()->SetOnlineAfterSetup(false);
  }

  std::vector<ShareWrapper> results(number_of_parties);
  std::vector<std::thread> threads;

  for (std::size_t i = 0; i < number_of_parties; ++i) {
    threads.emplace_back([i, &parties, &results]() {
      try {
        std::cout << "[THREAD] Party " << i << ": Starting thread.\n" << std::flush;

        auto& backend = *parties[i]->GetBackend();
        auto& comm_layer = backend.GetCommunicationLayer();
        comm_layer.Start();
        std::cout << "[THREAD] Party " << i << ": CommunicationLayer started.\n" << std::flush;

        auto& sp_provider = dynamic_cast<SpProviderFromOts&>(backend.GetSpProvider());
        std::cout << "[THREAD] Party " << i << ": Calling DistributeGlobalMacKey()\n" << std::flush;
        sp_provider.DistributeGlobalMacKey();

        std::cout << "[THREAD] Party " << i << ": Calling Run()...\n" << std::flush;
        parties[i]->Run();
        std::cout << "[THREAD] Party " << i << ": Run() completed.\n" << std::flush;

        std::cout << "[THREAD] Party " << i << ": Calling InputShareWithMac()...\n" << std::flush;
        auto share = sp_provider.InputShareWithMac(input_value, input_owner, bit_length, backend);
        results[i] = share;
        std::cout << "[THREAD] Party " << i << ": Finished InputShareWithMac().\n" << std::flush;

        parties[i]->Finish();
        std::cout << "[THREAD] Party " << i << ": Finish() completed.\n" << std::flush;

      } catch (const std::exception& e) {
        std::cerr << "[ERROR] Party " << i << ": Exception occurred: " << e.what() << std::endl << std::flush;
        FAIL();
      }
    });
  }

  for (auto& t : threads) {
    t.join();
  }

  std::cout << "[CHECKPOINT] All threads joined. Proceeding to validation...\n" << std::flush;

  for (std::size_t i = 0; i < number_of_parties; ++i) {
    const auto& share = results[i];
    const auto& wires = share->GetWires();

    ASSERT_EQ(wires.size(), 2u) << "[ERROR] Party " << i << ": Expected 2 wires (input, MAC)";
    const auto& input_wire_ptr = wires.at(0);
    const auto& mac_wire_ptr = wires.at(1);

    if (input_wire_ptr == nullptr) {
      std::cerr << "[ERROR] Party " << i << ": Input wire is null" << std::endl;
      FAIL();
    }
    if (mac_wire_ptr == nullptr) {
      std::cerr << "[ERROR] Party " << i << ": MAC wire is null" << std::endl;
      FAIL();
    }

    auto* input_wire = dynamic_cast<proto::ConstantArithmeticWire<std::uint64_t>*>(input_wire_ptr.get());
    auto* mac_wire = dynamic_cast<proto::ConstantArithmeticWire<std::uint64_t>*>(mac_wire_ptr.get());

    ASSERT_NE(input_wire, nullptr) << "[ERROR] Party " << i << ": Input wire is not ConstantArithmeticWire";
    ASSERT_NE(mac_wire, nullptr) << "[ERROR] Party " << i << ": MAC wire is not ConstantArithmeticWire";

    ASSERT_EQ(input_wire->GetValues().size(), 1u);
    ASSERT_EQ(mac_wire->GetValues().size(), 1u);

    const auto input_result = input_wire->GetValues().at(0);
    const auto mac_result = mac_wire->GetValues().at(0);

    std::cout << "[RESULT] Party " << i << ": input = " << input_result
              << ", mac = " << mac_result << std::endl << std::flush;

    if (i == input_owner) {
      EXPECT_EQ(input_result, input_value) << "[ERROR] Input owner received wrong value";
      EXPECT_NE(mac_result, 0u) << "[ERROR] Input owner has zero MAC value";
    } else {
      EXPECT_EQ(input_result, 0u) << "[ERROR] Non-owner should receive 0 as input value";
    }
  }

  std::cout << "[SUCCESS] InputShareWithMacValidation passed for all parties.\n" << std::flush;
}


