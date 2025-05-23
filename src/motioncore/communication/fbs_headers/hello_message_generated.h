// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_HELLOMESSAGE_ENCRYPTO_MOTION_COMMUNICATION_H_
#define FLATBUFFERS_GENERATED_HELLOMESSAGE_ENCRYPTO_MOTION_COMMUNICATION_H_

#include "flatbuffers/flatbuffers.h"

namespace encrypto {
namespace motion {
namespace communication {

struct HelloMessage;
struct HelloMessageBuilder;

struct HelloMessage FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef HelloMessageBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_SOURCE_ID = 4,
    VT_DESTINATION_ID = 6,
    VT_NUMBER_OF_PARTIES = 8,
    VT_INPUT_SHARING_SEED = 10,
    VT_GLOBAL_SHARING_SEED = 12,
    VT_FIXED_KEY_AES_SEED = 14,
    VT_ONLINE_AFTER_SETUP = 16,
    VT_MOTION_VERSION_MAJOR = 18,
    VT_MOTION_VERSION_MINOR = 20,
    VT_MOTION_VERSION_PATCH = 22
  };
  uint16_t source_id() const {
    return GetField<uint16_t>(VT_SOURCE_ID, 0);
  }
  uint16_t destination_id() const {
    return GetField<uint16_t>(VT_DESTINATION_ID, 0);
  }
  uint16_t number_of_parties() const {
    return GetField<uint16_t>(VT_NUMBER_OF_PARTIES, 0);
  }
  const flatbuffers::Vector<uint8_t> *input_sharing_seed() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_INPUT_SHARING_SEED);
  }
  const flatbuffers::Vector<uint8_t> *global_sharing_seed() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_GLOBAL_SHARING_SEED);
  }
  const flatbuffers::Vector<uint8_t> *fixed_key_aes_seed() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_FIXED_KEY_AES_SEED);
  }
  bool online_after_setup() const {
    return GetField<uint8_t>(VT_ONLINE_AFTER_SETUP, 0) != 0;
  }
  uint16_t motion_version_major() const {
    return GetField<uint16_t>(VT_MOTION_VERSION_MAJOR, 0);
  }
  uint16_t motion_version_minor() const {
    return GetField<uint16_t>(VT_MOTION_VERSION_MINOR, 0);
  }
  uint16_t motion_version_patch() const {
    return GetField<uint16_t>(VT_MOTION_VERSION_PATCH, 0);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<uint16_t>(verifier, VT_SOURCE_ID) &&
           VerifyField<uint16_t>(verifier, VT_DESTINATION_ID) &&
           VerifyField<uint16_t>(verifier, VT_NUMBER_OF_PARTIES) &&
           VerifyOffset(verifier, VT_INPUT_SHARING_SEED) &&
           verifier.VerifyVector(input_sharing_seed()) &&
           VerifyOffset(verifier, VT_GLOBAL_SHARING_SEED) &&
           verifier.VerifyVector(global_sharing_seed()) &&
           VerifyOffset(verifier, VT_FIXED_KEY_AES_SEED) &&
           verifier.VerifyVector(fixed_key_aes_seed()) &&
           VerifyField<uint8_t>(verifier, VT_ONLINE_AFTER_SETUP) &&
           VerifyField<uint16_t>(verifier, VT_MOTION_VERSION_MAJOR) &&
           VerifyField<uint16_t>(verifier, VT_MOTION_VERSION_MINOR) &&
           VerifyField<uint16_t>(verifier, VT_MOTION_VERSION_PATCH) &&
           verifier.EndTable();
  }
};

struct HelloMessageBuilder {
  typedef HelloMessage Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_source_id(uint16_t source_id) {
    fbb_.AddElement<uint16_t>(HelloMessage::VT_SOURCE_ID, source_id, 0);
  }
  void add_destination_id(uint16_t destination_id) {
    fbb_.AddElement<uint16_t>(HelloMessage::VT_DESTINATION_ID, destination_id, 0);
  }
  void add_number_of_parties(uint16_t number_of_parties) {
    fbb_.AddElement<uint16_t>(HelloMessage::VT_NUMBER_OF_PARTIES, number_of_parties, 0);
  }
  void add_input_sharing_seed(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> input_sharing_seed) {
    fbb_.AddOffset(HelloMessage::VT_INPUT_SHARING_SEED, input_sharing_seed);
  }
  void add_global_sharing_seed(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> global_sharing_seed) {
    fbb_.AddOffset(HelloMessage::VT_GLOBAL_SHARING_SEED, global_sharing_seed);
  }
  void add_fixed_key_aes_seed(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> fixed_key_aes_seed) {
    fbb_.AddOffset(HelloMessage::VT_FIXED_KEY_AES_SEED, fixed_key_aes_seed);
  }
  void add_online_after_setup(bool online_after_setup) {
    fbb_.AddElement<uint8_t>(HelloMessage::VT_ONLINE_AFTER_SETUP, static_cast<uint8_t>(online_after_setup), 0);
  }
  void add_motion_version_major(uint16_t motion_version_major) {
    fbb_.AddElement<uint16_t>(HelloMessage::VT_MOTION_VERSION_MAJOR, motion_version_major, 0);
  }
  void add_motion_version_minor(uint16_t motion_version_minor) {
    fbb_.AddElement<uint16_t>(HelloMessage::VT_MOTION_VERSION_MINOR, motion_version_minor, 0);
  }
  void add_motion_version_patch(uint16_t motion_version_patch) {
    fbb_.AddElement<uint16_t>(HelloMessage::VT_MOTION_VERSION_PATCH, motion_version_patch, 0);
  }
  explicit HelloMessageBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<HelloMessage> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<HelloMessage>(end);
    return o;
  }
};

inline flatbuffers::Offset<HelloMessage> CreateHelloMessage(
    flatbuffers::FlatBufferBuilder &_fbb,
    uint16_t source_id = 0,
    uint16_t destination_id = 0,
    uint16_t number_of_parties = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> input_sharing_seed = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> global_sharing_seed = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> fixed_key_aes_seed = 0,
    bool online_after_setup = false,
    uint16_t motion_version_major = 0,
    uint16_t motion_version_minor = 0,
    uint16_t motion_version_patch = 0) {
  HelloMessageBuilder builder_(_fbb);
  builder_.add_fixed_key_aes_seed(fixed_key_aes_seed);
  builder_.add_global_sharing_seed(global_sharing_seed);
  builder_.add_input_sharing_seed(input_sharing_seed);
  builder_.add_motion_version_patch(motion_version_patch);
  builder_.add_motion_version_minor(motion_version_minor);
  builder_.add_motion_version_major(motion_version_major);
  builder_.add_number_of_parties(number_of_parties);
  builder_.add_destination_id(destination_id);
  builder_.add_source_id(source_id);
  builder_.add_online_after_setup(online_after_setup);
  return builder_.Finish();
}

inline flatbuffers::Offset<HelloMessage> CreateHelloMessageDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    uint16_t source_id = 0,
    uint16_t destination_id = 0,
    uint16_t number_of_parties = 0,
    const std::vector<uint8_t> *input_sharing_seed = nullptr,
    const std::vector<uint8_t> *global_sharing_seed = nullptr,
    const std::vector<uint8_t> *fixed_key_aes_seed = nullptr,
    bool online_after_setup = false,
    uint16_t motion_version_major = 0,
    uint16_t motion_version_minor = 0,
    uint16_t motion_version_patch = 0) {
  auto input_sharing_seed__ = input_sharing_seed ? _fbb.CreateVector<uint8_t>(*input_sharing_seed) : 0;
  auto global_sharing_seed__ = global_sharing_seed ? _fbb.CreateVector<uint8_t>(*global_sharing_seed) : 0;
  auto fixed_key_aes_seed__ = fixed_key_aes_seed ? _fbb.CreateVector<uint8_t>(*fixed_key_aes_seed) : 0;
  return encrypto::motion::communication::CreateHelloMessage(
      _fbb,
      source_id,
      destination_id,
      number_of_parties,
      input_sharing_seed__,
      global_sharing_seed__,
      fixed_key_aes_seed__,
      online_after_setup,
      motion_version_major,
      motion_version_minor,
      motion_version_patch);
}

inline const encrypto::motion::communication::HelloMessage *GetHelloMessage(const void *buf) {
  return flatbuffers::GetRoot<encrypto::motion::communication::HelloMessage>(buf);
}

inline const encrypto::motion::communication::HelloMessage *GetSizePrefixedHelloMessage(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<encrypto::motion::communication::HelloMessage>(buf);
}

inline bool VerifyHelloMessageBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<encrypto::motion::communication::HelloMessage>(nullptr);
}

inline bool VerifySizePrefixedHelloMessageBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<encrypto::motion::communication::HelloMessage>(nullptr);
}

inline void FinishHelloMessageBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<encrypto::motion::communication::HelloMessage> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedHelloMessageBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<encrypto::motion::communication::HelloMessage> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace communication
}  // namespace motion
}  // namespace encrypto

#endif  // FLATBUFFERS_GENERATED_HELLOMESSAGE_ENCRYPTO_MOTION_COMMUNICATION_H_
