#include <algorithm>
#include <cstddef>
#include <iextoolslib/pcap_utils.hpp>
#include <iomanip>
#include <sstream>
#include <regex>

using namespace IEXTools;

std::string IEXTools::symbol_to_string(Symbol symbol) {
  return std::string(symbol.begin(), std::find(symbol.begin(), symbol.end(), ' '));
}

std::string IEXTools::mac_addr_formatter(std::array<std::byte, 6> addr) {
  std::stringstream ss;
  for (auto i = 0; i < addr.size(); ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << std::to_integer<int>(addr[i]) << std::dec;
    if (i < addr.size() - 1) {
      ss << ":";
    }
  }

  return ss.str();
}

std::string IEXTools::ip_addr_formatter(uint32_t addr) {
  std::stringstream ss;

  ss << (addr & 0xff) << "." << ((addr >> 8) & 0xff) << "." << ((addr >> 16) & 0xff) << "." << ((addr >> 24) & 0xff);

  return ss.str();
}

double IEXTools::price_to_double(Price price) {
  return price * 1e-4;
}