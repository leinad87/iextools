#ifndef __IEXTOOLSLIB_PCAP_UTILS_HPP__
#define __IEXTOOLSLIB_PCAP_UTILS_HPP__

#include <array>
#include <cstring>
#include <string>

#include "types.hpp"

namespace IEXTools {

template <typename T>
T read_bytes(pcap_cit_t& it) {
  T aux;
  std::memcpy(&aux, &(*it), sizeof(T));

  it += sizeof(T);

  return aux;
}

template <typename T>
void swap_endian(T& val) {
  union U {
    T val;
    std::array<std::uint8_t, sizeof(T)> raw;
  } src, dst;

  src.val = val;
  std::reverse_copy(src.raw.begin(), src.raw.end(), dst.raw.begin());
  val = dst.val;
}

std::string symbol_to_string(Symbol symbol);
std::string mac_addr_formatter(std::array<std::byte, 6> addr);
std::string ip_addr_formatter(uint32_t addr);
double price_to_double(Price price);

}  // namespace IEXTools

#endif
