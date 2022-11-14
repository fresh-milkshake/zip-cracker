#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>

enum Level
{
    DEBUG,
    CRITICAL,
    ERROR,
    WARNING,
    SUCCESS,
    INFO,
};

class Color
{
public:
    enum Fore
    {
        RED = 31,
        GREEN = 32,
        YELLOW = 33,
        BLUE = 34,
        MAGENTA = 35,
        CYAN = 36,
        WHITE = 37,
        GRAY = 90,
    };

    enum Back
    {
        BG_RED = 41,
        BG_GREEN = 42,
        BG_YELLOW = 43,
        BG_BLUE = 44,
        BG_MAGENTA = 45,
        BG_CYAN = 46,
        BG_WHITE = 47,
        BG_GRAY = 100,
    };

    enum Style
    {
        BOLD = 1,
        UNDERLINE = 4,
        BLINK = 5,
        REVERSE = 7,
        CONCEALED = 8
    };

    static void set_color(int color)
    {
        std::cout << "\033[" << color << "m";
    }

    static void reset_color()
    {
        std::cout << "\033[0m";
    }
};

class Logger
{
    std::string filename;
    Level logging_level;

    std::time_t current_time()
    {
        return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    }

    void print_formatted(std::time_t time, std::string message, Level level)
    {
        if (level < logging_level)
            return;

        char s[100];
        std::strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", std::localtime(&time));

        Color::set_color(Color::Fore::GRAY);
        std::cout << "[" << s << "] ";
        Color::reset_color();

        // print level label
        switch (level)
        {
        case Level::INFO:
            Color::set_color(Color::Fore::CYAN);
            std::cout << std::setw(10) << "[INFO]";
            break;
        case Level::WARNING:
            Color::set_color(Color::Fore::YELLOW);
            std::cout << std::setw(10) << "[WARNING]";
            break;
        case Level::SUCCESS:
            Color::set_color(Color::Fore::GREEN);
            std::cout << std::setw(10) << "[SUCCESS]";
            break;
        case Level::DEBUG:
            Color::set_color(Color::Fore::BLUE);
            std::cout << std::setw(10) << "[DEBUG]";
            break;
        case Level::ERROR:
            Color::set_color(Color::Fore::RED);
            std::cout << std::setw(10) << "[ERROR]";
            break;
        case Level::CRITICAL:
            Color::set_color(Color::Fore::RED);
            Color::set_color(Color::Back::BG_RED);
            std::cout << std::setw(10) << "[CRITICAL]";
            break;
        default:
            Color::set_color(Color::Fore::WHITE);
            std::cout << std::setw(10) << "[UNKNOWN]";
            break;
        }
        Color::reset_color();
        std::cout << " ";

        // print message
        std::cout << message << std::endl;
    }

public:
    Logger(std::string filename, Level level)
    {
        this->filename = filename;
        logging_level = level;
    }

    void log(std::string message, Level level)
    {
        print_formatted(current_time(), message, level);
    }

    void info(std::string message)
    {
        print_formatted(current_time(), message, Level::INFO);
    }

    void warn(std::string message)
    {
        print_formatted(current_time(), message, Level::WARNING);
    }

    void success(std::string message)
    {
        print_formatted(current_time(), message, Level::SUCCESS);
    }

    void debug(std::string message)
    {
        print_formatted(current_time(), message, Level::DEBUG);
    }


    void error(std::string message)
    {
        print_formatted(current_time(), message, Level::ERROR);
    }

    void critical(std::string message)
    {
        print_formatted(current_time(), message, Level::CRITICAL);
    }
};

void test_logger()
{
    Logger logger("test.log", Level::INFO);
    logger.info("Hello, world!");
    logger.warn("Hello, world!");
    logger.success("Hello, world!");
    logger.error("Hello, world!");
    logger.critical("Hello, world!");
}

// int main()
// {
//     test_logger();
//     return 0;
// }