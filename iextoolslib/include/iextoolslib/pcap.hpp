#ifndef __IEXTOOLSLIB_PCAP_HPP__
#define __IEXTOOLSLIB_PCAP_HPP__

#include <cstddef>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "pcap_frames.hpp"

namespace IEXTools {

struct PcapReader {
  explicit PcapReader(const std::string& file_path);

  struct Iterator {
    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = PcapFrame;
    using pointer = PcapFrame*;
    using reference = PcapFrame&;

    explicit Iterator(pointer ptr) : m_ptr(ptr){};

    reference operator*() const { return *m_ptr; }
    pointer operator->() { return m_ptr; }
    Iterator& operator++() {
      m_ptr++;
      return *this;
    }
    Iterator operator++(int) {
      Iterator tmp = *this;
      ++(*this);
      return tmp;
    }
    friend bool operator==(const Iterator& a, const Iterator& b) { return a.m_ptr == b.m_ptr; };
    friend bool operator!=(const Iterator& a, const Iterator& b) { return a.m_ptr != b.m_ptr; };

   private:
    pointer m_ptr;
  };

  Iterator begin() { return Iterator(&frames.at(0)); }
  Iterator end() {
    auto i = frames.end();
    return Iterator(&(*i));
  }

 private:
  [[nodiscard]] static std::size_t get_file_size(const std::string& path);
  std::vector<std::byte> load_data();
  std::vector<PcapFrame> get_frames();
  static std::unique_ptr<PcapBlock> get_block(int block_type, pcap_cit_t it_begin, pcap_cit_t it_end);
  static std::unique_ptr<EnhancedPacketBlock> get_enhanced_packet_block(pcap_cit_t it_begin, pcap_cit_t it_end);

  const std::string file_path;
  const size_t file_size;
  const std::vector<std::byte> data;
  std::vector<PcapFrame> frames;
};
}  // namespace IEXTools

std::ostream& operator<<(std::ostream& os, const IEXTools::PcapFrame& obj);
std::ostream& operator<<(std::ostream& os, const IEXTools::EnhancedPacketBlock& obj);

#endif