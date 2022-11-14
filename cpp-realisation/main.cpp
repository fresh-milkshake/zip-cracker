#include <atomic>
#include <thread>
#include <stdio.h>
#include <zlib.h>

// include external classes
#include "parse_args.cpp"
// #include "logging.cpp" --> already included in parse_args.cpp

Logger logger("main.cpp", Level::INFO);

void find_password(std::string zip_file, std::string dictionary_file, std::string password)
{
	// ???
}

int main(int argc, char **argv)
{
	// collect args
	Parser parser;
	parser.add_arg("ZIP", "Input zip file", Type::FILE_PATH);
	parser.add_arg("DICTIONARY", "Input dictionary file", Type::FILE_PATH);
	parser.add_arg(Option("-v", "--verbose", "Enable verbose mode", Type::FLAG, false, "false"));
	parser.default_help();

	bool success = parser.validate(argc, argv);

	if (!success)
		return 1;

	// get args
	std::string zip_path = parser.get_arg("ZIP");
	std::string dict_path = parser.get_arg("DICTIONARY");
	bool verbose = parser.get_arg("-v") == "true";

	// show args
	logger.debug("Zip path: " + zip_path);
	logger.debug("Dictionary path: " + dict_path);
	logger.debug("Verbose: " + std::string(verbose ? "true" : "false"));

	logger.info("Starting zip-cracker");
	int workers_count = std::thread::hardware_concurrency();
	logger.debug("Virtual cores count: " + std::to_string(workers_count));

	std::vector<std::thread> workers;
	std::atomic<bool> found(false);

	// start workers
}
