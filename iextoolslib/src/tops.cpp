//
// Created by Juan on 24/12/2020.
//

#include <iextoolslib/tops.hpp>

using namespace IEXTools;

TopsReader::TopsReader(const std::string& file_path)
    : file_path(file_path), pcap(file_path), messages(get_messages()) {}

std::vector<TopsMessage> TopsReader::get_messages() {
  std::vector<TopsMessage> m;

  return m;
}
