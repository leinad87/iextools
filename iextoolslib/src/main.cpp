#include <filesystem>
#include <functional>
#include <iextoolslib/iextools.hpp>
#include <iextoolslib/tops.hpp>
#include <iomanip>
#include <iostream>
#include <tuple>
#include <vector>

void print_version();
void print_help();

struct Opts {
  static Opts& instance() {
    static Opts _instance;
    return _instance;
  }

  Opts(Opts const&) = delete;
  void operator=(Opts const&) = delete;

 private:
  Opts() : opts({
    {"-h", "--help", "display this help and exit", print_help},
    {"-v", "--version", "output version information and exit", print_version}}) {}

 public:
  std::vector<std::tuple<std::string, std::string, std::string, std::function<void(void)>>> opts;
};



void print_version() {
  using namespace IEXTools;
  std::cout << "IEXTools " << __major_version__ << "." << __minor_version__ << std::endl;
}

void print_help() {
  using namespace std;

  cout << "Usage: iex-tools [FILE] [OUT_DIR]\n";
  cout << "Parses a pcap-ng dump file containing IEX TOPS data.\n\n";

  auto opts = Opts::instance().opts;

  for (const auto& opt : opts) {
    const auto& [short_flag, flag, description, func] = opt;
    cout << setfill(' ') << setw(5) << right << short_flag << " " << setw(24) << left << flag << "  " << description
         << "\n";
  }
}

int main(int argc, char* argv[]) {
  if (argc == 3) {
    std::string arg1{argv[1]};
    std::string arg2{argv[2]};

    auto opts = Opts::instance().opts;
    if (arg1.starts_with("-")) {
      for (const auto& opt : opts) {
        const auto& [short_flag, flag, description, func] = opt;
        if (arg1 == short_flag || arg1 == flag) {
          func();
          return 0;
        }
      }
    } else {
      // no flag, then it is interpret as a path
      if (std::filesystem::exists(arg1)) {
        if (std::filesystem::exists(arg2) && std::filesystem::is_directory(arg2) && std::filesystem::is_empty(arg2)) {
          IEXTools::TopsReader tops(arg1, arg2);
          return 0;
        } else {
          std::cerr << "Out dir '" << arg2 << "' must be an valid empty directory.\n";
          return 1;
        }
      } else {
        std::cerr << "File '" << arg1 << "' does not exist.\n";
        return 1;
      }
    }
  }

  print_help();

  return 0;
}