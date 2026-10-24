// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
#include <gtest/gtest.h>
#include <algorithm>
#include <vector>
#include "rgw_sts_jwks.h"

using rgw::auth::sts::detail::select_jwks_keys;

namespace {

std::vector<size_t> select_keys(const std::vector<std::string>& keys,
                                std::optional<std::string> token_kid)
{
  std::string jwks = "[";
  for (size_t i = 0; i < keys.size(); ++i) {
    if (i != 0) {
      jwks += ',';
    }
    jwks += keys[i];
  }
  jwks += ']';
  JSONParser parser;
  if (!parser.parse(jwks.c_str(), jwks.size())) {
    ADD_FAILURE() << "Invalid test JWKS";
    return {};
  }
  std::vector<JSONObj*> all_keys;
  for (auto key = parser.find_first(); !key.end(); ++key) {
    all_keys.push_back(*key);
  }
  std::vector<size_t> selected;
  for (auto key : select_jwks_keys(parser, token_kid)) {
    selected.push_back(std::find(all_keys.begin(), all_keys.end(), key) -
                       all_keys.begin());
  }
  return selected;
}

} // anonymous namespace

TEST(STSJwks, SelectsMatchingKeyAndSkipsAnonymousKey)
{
  const std::vector<std::string> keys = {
    R"({"kid":"old","x5c":["unused"]})",
    R"({"n":"anonymous","e":"AQAB"})",
    R"({"kid":"current","n":"selected","e":"AQAB"})"};
  EXPECT_EQ((std::vector<size_t>{2}), select_keys(keys, "current"));
}

TEST(STSJwks, MissingTokenKidTriesAllKeys)
{
  const std::vector<std::string> keys = {R"({"kid":"a"})", R"({})"};
  EXPECT_EQ((std::vector<size_t>{0, 1}), select_keys(keys, std::nullopt));
}

TEST(STSJwks, UnknownTokenKidTriesAllKeys)
{
  const std::vector<std::string> keys = {R"({"kid":"a"})", R"({})"};
  EXPECT_EQ((std::vector<size_t>{0, 1}), select_keys(keys, "unknown"));
}

TEST(STSJwks, AnonymousJwksTriesAllKeys)
{
  const std::vector<std::string> keys = {R"({"n":"first"})", R"({"n":"second"})"};
  EXPECT_EQ((std::vector<size_t>{0, 1}), select_keys(keys, "current"));
}

TEST(STSJwks, SelectsAllKeysWithSameKid)
{
  const std::vector<std::string> keys = {
    R"({"kid":"current","x5c":["first"]})",
    R"({"kid":"other"})",
    R"({"kid":"current","n":"second","e":"AQAB"})"};
  EXPECT_EQ((std::vector<size_t>{0, 2}), select_keys(keys, "current"));
}

TEST(STSJwks, EmptyKidIsDistinctFromMissingKid)
{
  const std::vector<std::string> keys = {R"({})", R"({"kid":""})", R"({"kid":"a"})"};
  EXPECT_EQ((std::vector<size_t>{1}), select_keys(keys, ""));
}

TEST(STSJwks, UnmatchedEmptyKidTriesAllKeys)
{
  const std::vector<std::string> keys = {R"({})", R"({"kid":"a"})"};
  EXPECT_EQ((std::vector<size_t>{0, 1}), select_keys(keys, ""));
}

TEST(STSJwks, EmptyJwksSelectsNothing)
{
  EXPECT_TRUE(select_keys({}, "current").empty());
  EXPECT_TRUE(select_keys({}, std::nullopt).empty());
}

TEST(STSJwks, NonObjectEntriesDoNotPreventSelectingLaterKey)
{
  const std::vector<std::string> keys = {R"("invalid")", "null", R"({"kid":"current"})"};
  EXPECT_EQ((std::vector<size_t>{2}), select_keys(keys, "current"));
}
