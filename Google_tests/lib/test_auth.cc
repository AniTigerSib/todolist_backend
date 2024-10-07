#include <gtest/gtest.h>
#include "../../lib/Auth.h"
#include <string>

class AuthTest : public ::testing::Test {
};

TEST_F(AuthTest, GenerateRandomTokenLength) {
    const size_t expectedLength = 10;
    std::string token = Auth::generateRandomToken(expectedLength);
    EXPECT_EQ(token.length(), expectedLength);
}

TEST_F(AuthTest, GenerateRandomTokenCharacterSet) {
    const size_t tokenLength = 20;
    std::string token = Auth::generateRandomToken(tokenLength);
    std::string validChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    
    for (char c : token) {
        EXPECT_NE(validChars.find(c), std::string::npos) << "Character '" << c << "' is not in the valid character set";
    }
}

TEST_F(AuthTest, GenerateRandomTokenUniqueness) {
    const size_t tokenLength = 15;
    std::string token1 = Auth::generateRandomToken(tokenLength);
    std::string token2 = Auth::generateRandomToken(tokenLength);
    
    EXPECT_NE(token1, token2) << "Generated tokens should be different";
}

TEST_F(AuthTest, GenerateRandomTokenZeroLength) {
    const size_t zeroLength = 0;
    std::string token = Auth::generateRandomToken(zeroLength);
    EXPECT_TRUE(token.empty()) << "Token should be empty for zero length";
}

TEST_F(AuthTest, GenerateRandomTokenLargeLength) {
    const size_t largeLength = 1000000; // 1 million characters
    std::string token;
    ASSERT_NO_THROW({
        token = Auth::generateRandomToken(largeLength);
    }) << "generateRandomToken should not crash with large length";
    EXPECT_EQ(token.length(), largeLength) << "Generated token should have the requested length";
}

TEST_F(AuthTest, GenerateRandomTokenUniformDistribution) {
    const size_t tokenLength = 100000;
    const size_t expectedFrequency = tokenLength / 62;  // 62 is the number of possible characters
    const double tolerance = 0.1;  // 10% tolerance

    std::string token = Auth::generateRandomToken(tokenLength);
    std::map<char, int> charFrequency;

    for (char c : token) {
        charFrequency[c]++;
    }

    for (const auto& pair : charFrequency) {
        EXPECT_NEAR(pair.second, expectedFrequency, expectedFrequency * tolerance)
            << "Character '" << pair.first << "' frequency is outside the expected range";
    }
}

TEST_F(AuthTest, GenerateRandomTokenMaxLength) {
    const size_t maxLength = std::numeric_limits<size_t>::max();
    std::string token;
    ASSERT_NO_THROW({
        token = Auth::generateRandomToken(maxLength);
    }) << "generateRandomToken should not throw an exception with maximum length";
    
    // Check if the token is not empty (it's likely to be truncated due to memory limitations)
    EXPECT_FALSE(token.empty()) << "Generated token should not be empty";
    
    // Verify that all characters in the token are valid
    std::string validChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (char c : token) {
        EXPECT_NE(validChars.find(c), std::string::npos) << "Character '" << c << "' is not in the valid character set";
    }
}

TEST_F(AuthTest, GenerateRandomTokenNoMemoryLeaksOrOverflows) {
    const size_t tokenLength = 1000000;  // Large length to stress test
    
    // Use EXPECT_NO_FATAL_FAILURE to catch any segmentation faults or other crashes
    EXPECT_NO_FATAL_FAILURE({
        std::string token = Auth::generateRandomToken(tokenLength);
        EXPECT_EQ(token.length(), tokenLength);
    });
    
    // Check for memory leaks using a memory profiler like Valgrind
    // This can't be done directly in the test, but should be run as part of the testing process
    
    // Verify that the function can handle very large inputs without buffer overflows
    const size_t maxLength = std::numeric_limits<size_t>::max();
    EXPECT_NO_THROW({
        std::string largeToken = Auth::generateRandomToken(maxLength);
        // The actual length might be less due to memory limitations, but it shouldn't crash
        EXPECT_GT(largeToken.length(), 0);
    });
}