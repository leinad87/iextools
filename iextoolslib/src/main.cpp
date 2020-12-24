#include <filesystem>
#include <functional>
#include <iextoolslib/iextools.hpp>
#include <iextoolslib/tops.hpp>
#include <iomanip>
#include <iostream>
#include <tuple>
#include <vector>

void iex_tops_run();
void print_version();
void print_help();

std::vector<std::tuple<std::string, std::string, std::string, std::function<void(void)>>> opts{
    {"-h", "--help", "display this help and exit", print_help},
    {"-v", "--version", "output version information and exit", print_version}};

void iex_tops_run() {
  using namespace IEXTools;
  TopsReader reader("/Users/juan/Downloads/test.pcap");
}

void print_version() {
  using namespace IEXTools;
  std::cout << "IEXTools " << __major_version__ << "." << __minor_version__ << std::endl;
}

void print_help() {
  using namespace std;

  cout << "Usage: iex-tools [FILE]\n";
  cout << "Parses a pcap-ng dump file containing IEX TOPS data.\n\n";

  for (const auto& opt : opts) {
    const auto& [short_flag, flag, description, func] = opt;
    cout << setfill(' ') << setw(5) << right << short_flag << " " << setw(24) << left << flag << "  " << description
         << "\n";
  }
}

int main(int argc, char* argv[]) {
  if (argc == 2) {
    std::string arg{argv[1]};

    if (arg.starts_with("-")) {
      for (const auto& opt : opts) {
        const auto& [short_flag, flag, description, func] = opt;
        if (arg == short_flag || arg == flag) {
          func();
          return 0;
        }
      }
    } else {
      // no flag, then it is interpret as a path
      if (std::filesystem::exists(arg)) {
        return 0;
      } else {
        std::cerr << "File '" << arg << "' does not exist.\n";
        return 1;
      }
    }
  }

  print_help();

  return 0;
}