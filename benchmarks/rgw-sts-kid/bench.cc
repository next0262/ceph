#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include "rgw_sts_jwks.h"
#include "jwt-cpp/jwt.h"

using Clock = std::chrono::steady_clock;
using rgw::auth::sts::detail::select_jwks_keys;
static size_t sink = 0;

std::string read_file(const std::string& path) {
  std::ifstream in(path);
  if (!in) throw std::runtime_error("Cannot open " + path);
  return {std::istreambuf_iterator<char>(in), {}};
}

bool verify_key(JSONObj* key, const jwt::decoded_jwt& decoded, size_t& attempts) {
  std::string kid, use;
  JSONDecoder::decode_json("kid", kid, key);
  if (JSONDecoder::decode_json("use", use, key) && use != "sig") return false;
  try {
    std::vector<std::string> x5c;
    if (JSONDecoder::decode_json("x5c", x5c, key)) {
      if (x5c.empty()) return false;
      std::string cert = "-----BEGIN CERTIFICATE-----\n" + x5c.front() + "\n-----END CERTIFICATE-----";
      ++attempts;
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::rs256{cert});
      verifier.verify(decoded);
      return true;
    }
    std::string kty, n, e;
    if (JSONDecoder::decode_json("kty", kty, key) && kty != "RSA") return false;
    if (JSONDecoder::decode_json("n", n, key) && JSONDecoder::decode_json("e", e, key)) {
      ++attempts;
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::rs256().setModulusAndExponent(n, e));
      verifier.verify(decoded);
      return true;
    }
  } catch (const std::exception&) {
    // Same continue-on-verification-failure behavior as RGW, with logging disabled.
  }
  return false;
}

enum class Mode { Original, Patched, UnknownKidRejected };
bool validate(const std::string& jwks, const std::string& token, Mode mode, size_t& attempts) {
  const auto decoded = jwt::decode(token);
  JSONParser parser;
  if (!parser.parse(jwks.c_str(), jwks.size())) throw std::runtime_error("bad fixture JSON");
  auto* keys = parser.find_obj("keys");
  if (!keys || !keys->is_array()) throw std::runtime_error("bad fixture keys");
  if (mode == Mode::Original) {
    auto serialized = keys->get_array_elements();
    for (auto& key : serialized) {
      JSONParser k_parser;
      if (k_parser.parse(key.c_str(), key.size()) && verify_key(&k_parser, decoded, attempts)) return true;
    }
    return false;
  }
  std::optional<std::string> kid;
  if (decoded.has_key_id()) kid = decoded.get_key_id();
  auto selected = select_jwks_keys(*keys, kid);
  if (mode == Mode::UnknownKidRejected && kid) {
    selected.erase(std::remove_if(selected.begin(), selected.end(), [&](JSONObj* key) {
      std::string key_kid;
      return !JSONDecoder::decode_json("kid", key_kid, key) || key_kid != *kid;
    }), selected.end());
  }
  for (auto* key : selected) {
    if (key->is_object() && verify_key(key, decoded, attempts)) return true;
  }
  return false;
}

template<class Fn> double median_us(Fn&& fn, int iterations) {
  for (int i=0; i<20; ++i) fn();
  std::vector<double> samples;
  for (int batch=0; batch<7; ++batch) {
    auto start=Clock::now();
    for (int i=0; i<iterations; ++i) fn();
    auto end=Clock::now();
    samples.push_back(std::chrono::duration<double,std::micro>(end-start).count()/iterations);
  }
  std::sort(samples.begin(), samples.end());
  return samples[samples.size()/2];
}

int main(int argc, char** argv) {
  try {
    const std::string root=argc>1 ? argv[1] : "fixtures";
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "# RS256/RSA-2048; median of 7 batches x 200 validations; 20 warmups.\n";
    std::cout << "# Includes JWT decode, JWKS parse, key selection and real signature verification.\n";
    std::cout << "# Excludes HTTP/DNS/TLS, thumbprint checks and logging.\n";
    std::cout << "path,keys,position,original_attempts,patched_attempts,original_us,patched_us,speedup,select_only_us,one_verify_us\n";
    if (argc < 3 || std::string(argv[2]) != "--semantics-only") {
    for (auto path : {"ne", "x5c"}) {
      for (int count : {1,4,8,16,32}) {
        auto jwks=read_file(root+"/"+path+"-"+std::to_string(count)+".json");
        std::vector<int> positions={0};
        if (count>1) { positions.push_back(count/2); positions.push_back(count-1); }
        for (int position : positions) {
          auto token=read_file(root+"/token-"+std::to_string(position)+".jwt");
          size_t original_attempts=0, patched_attempts=0;
          if (!validate(jwks,token,Mode::Original,original_attempts) ||
              !validate(jwks,token,Mode::Patched,patched_attempts)) throw std::runtime_error("valid token rejected");
          auto original=[&] { size_t a=0; if (!validate(jwks,token,Mode::Original,a)) throw std::runtime_error("baseline failed"); sink+=a; };
          auto patched=[&] { size_t a=0; if (!validate(jwks,token,Mode::Patched,a)) throw std::runtime_error("patched failed"); sink+=a; };
          double old_us, new_us;
          // Alternate ordering to reduce systematic warm-cache/thermal bias.
          if (position%2) {new_us=median_us(patched,200);old_us=median_us(original,200);}
          else {old_us=median_us(original,200);new_us=median_us(patched,200);}
          JSONParser parser;
          if (!parser.parse(jwks.c_str(),jwks.size())) throw std::runtime_error("fixture parse failed");
          auto* keys=parser.find_obj("keys");
          auto decoded=jwt::decode(token);
          std::optional<std::string> kid=decoded.get_key_id();
          auto matching=select_jwks_keys(*keys,kid);
          double select_us=median_us([&]{sink+=select_jwks_keys(*keys,kid).size();},3000);
          double verify_us=median_us([&]{size_t a=0;if (!verify_key(matching.at(0),decoded,a)) throw std::runtime_error("single verify failed");sink+=a;},200);
          std::cout << path << ',' << count << ',' << position+1 << ',' << original_attempts << ',' << patched_attempts
                    << ',' << old_us << ',' << new_us << ',' << old_us/new_us << ',' << select_us << ',' << verify_us << std::endl;
        }
      }
    }
    }
    std::cout << "# Semantic checks: token,original_accept,patched_accept,reject_unknown_accept\n";
    auto jwks=read_file(root+"/ne-4.json");
    for (auto name : {"missing", "unknown", "wrong-known", "empty"}) {
      auto token=read_file(root+"/"+name+".jwt");
      std::cout << name;
      for (auto mode : {Mode::Original,Mode::Patched,Mode::UnknownKidRejected}) {
        size_t a=0;std::cout << ',' << validate(jwks,token,mode,a);
      }
      std::cout << std::endl;
    }
    auto no_kid_token=read_file(root+"/missing.jwt");
    for (auto filename : {"ne-1.json", "ne-1-no-jwk-kid.json"}) {
      auto single=read_file(root+"/"+filename);
      std::cout << "missing/" << filename;
      for (auto mode : {Mode::Original,Mode::Patched,Mode::UnknownKidRejected}) {
        size_t a=0;
        bool accepted=validate(single,no_kid_token,mode,a);
        if (!accepted) throw std::runtime_error("valid single-key JWT without kid rejected");
        std::cout << ',' << accepted;
      }
      std::cout << std::endl;
    }
    std::cerr << "sink=" << sink << '\n';
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';return 1;
  }
}
