// Copyright 2024 Joao Brotas
// Some portions of this file may be subject to third-party copyrights.

/**
 * @file routes.h
 * @brief Defines the Routes class for handling different routes in the system.
 *
 * This file declares the `Routes` class, which provides static methods for
 * handling specific routes in the application, such as the "Hello" and "Echo"
 * routes. Each route handler processes incoming data and returns a response in
 * the form of a key-value pair.
 */

#ifndef INCLUDE_ROUTES_H_
#define INCLUDE_ROUTES_H_

#include <string>
#include <utility>

/**
 * @class Routes
 * @brief A class for handling routes in the application.
 *
 * The `Routes` class provides methods to handle different routes, such as the
 * "Hello" and "Echo" routes. Each method processes the given input data and
 * returns a corresponding response in the form of a string pair.
 */
class Routes {
 public:
  /**
   * @brief Constructor for the `Routes` class.
   *
   * The constructor initializes any necessary resources for handling routes.
   */
  explicit Routes();

  /**
   * @brief Destructor for the `Routes` class.
   *
   * The destructor cleans up any resources initialized by the constructor.
   */
  ~Routes();

  /**
   * @brief A static method for handling the "Hello" route.
   *
   * This method generates a response for the "Hello" route. It processes the
   * input data and returns a response as a pair of strings. The first string is
   * the response code, and the second string is the response message.
   *
   * @param data The input data for the route (typically user input).
   * @return A pair of strings, where the first string is the response code and
   * the second string is the message.
   */
  static std::pair<std::string, std::string> HelloHandler(
      const std::string &data);

  /**
   * @brief A static method for handling the "Echo" route.
   *
   * This method generates a response for the "Echo" route. It returns the input
   * data as a response, effectively "echoing" the data back to the user. The
   * response is returned as a pair of strings, where the first string is the
   * response code and the second string is the echoed message.
   *
   * @param data The input data for the route (typically user input).
   * @return A pair of strings, where the first string is the response code and
   * the second string is the echoed message.
   */
  static std::pair<std::string, std::string> EchoHandler(
      const std::string &data);
};

#endif  // INCLUDE_ROUTES_H_
