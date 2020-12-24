//
// Created by Juan on 24/12/2020.
//

#ifndef IEX_TOOLS_TOPS_HPP
#define IEX_TOOLS_TOPS_HPP

#include <string>
#include <vector>

#include "pcap.hpp"
#include "tops_messages.hpp"

namespace IEXTools {
struct TopsReader {
  TopsReader(const std::string& file_path);

 private:
  std::vector<TopsMessage> get_messages();

  const std::string file_path;
  PcapReader pcap;
  std::vector<TopsMessage> messages;
};

}  // namespace IEXTools

#endif  // IEX_TOOLS_TOPS_HPP
