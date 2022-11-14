
#include <vector>
#include <map>
#include <fstream>

#include "logging.cpp"

Logger args_logger("parse_args.cpp", Level::DEBUG);

enum Type {
    TEXT,
    FILE_PATH,
    INTEGER,
    FLAG
};

class Argument {
public:
    std::string name;
    std::string description;
    Type type;
    int position;

    Argument(std::string name, std::string description, Type type, int position) {
        this->name = name;
        this->description = description;
        this->type = type;
        this->position = position;
    }

    bool validate(std::string value) {
        if (this->type == Type::TEXT) {
            return true;
        } else if (this->type == Type::FILE_PATH) {
            std::ifstream file(value);
            return file.good();
        } else if (this->type == Type::INTEGER) {
            try {
                std::stoi(value);
                return true;
            } catch (std::invalid_argument) {
                return false;
            }
        } else if (this->type == Type::FLAG) {
            return value == "true" || value == "false";
        } else {
            return false;
        }
    }
};

class Option {
public:
    std::string short_name;
    std::string long_name;
    std::string description;
    Type type;
    bool required;
    std::string default_value;

    Option(std::string short_name, std::string long_name, std::string description, Type type, bool required, std::string default_value) {
        this->short_name = short_name;
        this->long_name = long_name;
        this->description = description;
        this->type = type;
        this->required = required;
        this->default_value = default_value;
    }

    Option(std::string short_name, std::string long_name, std::string description, Type type) {
        this->short_name = short_name;
        this->long_name = long_name;
        this->description = description;
        this->type = type;
        this->required = true;
    }

    bool validate(std::string value) {
        if (this->type == Type::TEXT) {
            return true;
        } else if (this->type == Type::FILE_PATH) {
            std::ifstream file(value);
            return file.good();
        } else if (this->type == Type::INTEGER) {
            try {
                std::stoi(value);
                return true;
            } catch (std::invalid_argument) {
                return false;
            }
        } else if (this->type == Type::FLAG) {
            return value == "true" || value == "false";
        } else {
            return false;
        }
    }
};


class Parser {
private:
    std::vector<Argument> arguments;
    std::vector<Option> options;
    int next_position = 0;
    std::map<std::string, std::string> parsed_params;

public:
    Parser() {}
    ~Parser() {}

    void show_help() {
        std::cout << "Usage: " << std::endl;
        for (Argument arg : this->arguments) {
            std::cout << "  " << arg.name << " - " << arg.description << std::endl;
        }
        for (Option opt : this->options) {
            std::cout << "  " << opt.short_name << ", " << opt.long_name << " - " << opt.description << std::endl;
        }
    }

    bool validate(int argc, char* argv[]) {
        args_logger.info("Validating arguments...");
        std::vector<std::string> given_args;
        
        // collect given args
        for (int i = 1; i < argc; i++) {
            given_args.push_back(argv[i]);
        }

        args_logger.debug("Found " + std::to_string(given_args.size()) + " parameters");

        // validate arguments
        // if first arg is help and we have option with help - show help
        if (given_args[0] == "-h" || given_args[0] == "--help") {
            for (Option opt : this->options) {
                if (opt.short_name == "-h" || opt.long_name == "--help") {
                    this->show_help();
                    return false;
                }
            }
        }

        for (int i = 0; i < this->arguments.size(); i++) {
            Argument arg = this->arguments[i];
            if (arg.position >= given_args.size()) {
                args_logger.error("Argument " + arg.name + " is required");
                return false;
            }
            std::string value = given_args[arg.position];
            args_logger.debug("Validating argument " + arg.name + " with value " + value);
            if (!arg.validate(value)) {
                args_logger.error("Argument " + arg.name + " is invalid");
                return false;
            }
            this->parsed_params[arg.name] = value;
        }

        args_logger.debug("Arguments are valid");

        // validate options
        for (int i = 0; i < this->options.size(); i++) {
            for (int j = 0; j < given_args.size(); j++) {
                Option opt = this->options[i];
                std::string value = given_args[j];
                if (value == opt.short_name || value == opt.long_name) {
                    args_logger.debug("Found existing option \"" + value + "\" of type " + std::to_string(opt.type));
                    if (opt.type == Type::FLAG) {
                        this->parsed_params[opt.short_name] = "true";
                    } else {
                        if (j + 1 >= given_args.size()) {
                            args_logger.error("Option " + opt.long_name + " requires value");
                            return false;
                        }
                        std::string value = given_args[j + 1];
                        if (!opt.validate(value)) {
                            args_logger.error("Invalid value for option " + opt.long_name);
                            return false;
                        }
                        this->parsed_params[opt.long_name] = value;
                    }
                }
            }
        }

        args_logger.debug("Options are valid");
        args_logger.success("Arguments parsed successfully");
        if (this->parsed_params.find("help") != this->parsed_params.end())
            this->show_help();
        return true;
    }

    void add_arg(std::string name, std::string description, Type type) {
        Argument arg(name, description, type, next_position);
        this->arguments.push_back(arg);
        this->next_position++;
    }

    void add_arg(Option option) {
        this->options.push_back(option);
    }

    void default_help() {
        Option help("-h", "--help", "Shows help message", Type::FLAG);
        this->options.push_back(help);
    }

    std::string get_arg(std::string name) {
        return this->parsed_params[name];
    }
};


void test() {
    std::cout << "Test started" << std::endl;
    char* argv[] = {"./main", "test.txt", "test.txt", "-v", "-h"};
    
    Parser parser;
    parser.add_arg("zip", "Path to zip file", Type::FILE_PATH);
    parser.add_arg("dict", "Path to dictionary file", Type::FILE_PATH);
    parser.add_arg(Option("-h", "--help", "Show help", Type::FLAG, false, "false"));
    parser.add_arg(Option("-v", "--verbose", "Show verbose output", Type::FLAG, false, "false"));
    bool code = parser.validate(5, argv);
    std::cout << "Code: " << code << std::endl;
    std::string zip_path = parser.get_arg("zip");
    std::string dict_path = parser.get_arg("dict");
    std::string help = parser.get_arg("-h");
    std::string verbose = parser.get_arg("-v");
    std::cout << "Zip path: " << zip_path << std::endl;
    std::cout << "Dict path: " << dict_path << std::endl;
    std::cout << "Help: " << help << std::endl;
    std::cout << "Verbose: " << verbose << std::endl;
}
