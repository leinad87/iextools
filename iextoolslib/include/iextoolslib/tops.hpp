#ifndef IEX_TOOLS_TOPS_HPP
#define IEX_TOOLS_TOPS_HPP

#include <filesystem>
#include <iextoolslib/pcap.hpp>
#include <iextoolslib/tops_messages.hpp>
#include <map>
#include <memory>
#include <vector>

namespace IEXTools {
struct TopsReader {
  TopsReader(const std::string& file_path, const std::string& out_dir);

  void parse_data();

 private:
  std::vector<std::unique_ptr<TopsMessage>> get_messages(EnhancedPacketBlock* packet);

  PcapReader pcap;
  std::map<std::string, std::vector<std::string>> data;
  std::filesystem::path out_dir;

  void dump_files() const;
};

}  // namespace IEXTools

#endif  // IEX_TOOLS_TOPS_HPP
