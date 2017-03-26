/*   
   Raphael Nascimento raphasil@gmail.com
*/

#include <iostream>
#include <cstring>
#include <tr1/cstdint>
#include "security_sha_digest.h"
#include "stdio.h"
#include "stdlib.h"

namespace ph { namespace security {
	
	namespace 
	{
		
		typedef std::tr1::uint32_t uint32_t;
		typedef std::tr1::uint64_t uint64_t;
		
		inline unsigned int rotleft(uint32_t value, int shift) 
		{
			if ((shift &= 31) == 0) return value;
			return (value << shift) | (value >> (32 - shift));
		}
 
		inline unsigned int rotright(uint32_t value, int shift) 
		{
			if ((shift &= 31) == 0) return value;
			return (value >> shift) | (value << (32 - shift));
		}
		
	}

#define BSWAP32(x) 		(((uint32_t)(x) << 24) | \
						 ((uint32_t)(x) >> 24) | \
						 (((uint32_t)(x) << 8) & 0xff0000L) | \
						 (((uint32_t)(x) >> 8) & 0xff00L))
						

	// SHA-256 constants
	namespace constants {
		
		const uint32_t h0 = (0x6a09e667);
		const uint32_t h1 = (0xbb67ae85);
		const uint32_t h2 = (0x3c6ef372);
		const uint32_t h3 = (0xa54ff53a);
		const uint32_t h4 = (0x510e527f);
		const uint32_t h5 = (0x9b05688c);
		const uint32_t h6 = (0x1f83d9ab);
		const uint32_t h7 = (0x5be0cd19);
		
		const uint32_t k[64] = 
		{
			(0x428a2f98), (0x71374491), (0xb5c0fbcf), (0xe9b5dba5), 
			(0x3956c25b), (0x59f111f1), (0x923f82a4), (0xab1c5ed5),
			(0xd807aa98), (0x12835b01), (0x243185be), (0x550c7dc3), 
			(0x72be5d74), (0x80deb1fe), (0x9bdc06a7), (0xc19bf174),
			(0xe49b69c1), (0xefbe4786), (0x0fc19dc6), (0x240ca1cc), 
			(0x2de92c6f), (0x4a7484aa), (0x5cb0a9dc), (0x76f988da),
			(0x983e5152), (0xa831c66d), (0xb00327c8), (0xbf597fc7), 
			(0xc6e00bf3), (0xd5a79147), (0x06ca6351), (0x14292967),
			(0x27b70a85), (0x2e1b2138), (0x4d2c6dfc), (0x53380d13), 
			(0x650a7354), (0x766a0abb), (0x81c2c92e), (0x92722c85),
			(0xa2bfe8a1), (0xa81a664b), (0xc24b8b70), (0xc76c51a3), 
			(0xd192e819), (0xd6990624), (0xf40e3585), (0x106aa070),
			(0x19a4c116), (0x1e376c08), (0x2748774c), (0x34b0bcb5), 
			(0x391c0cb3), (0x4ed8aa4a), (0x5b9cca4f), (0x682e6ff3),
			(0x748f82ee), (0x78a5636f), (0x84c87814), (0x8cc70208), 
			(0x90befffa), (0xa4506ceb), (0xbef9a3f7), (0xc67178f2)
		};
	}
		
	namespace details {
	
		inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
		{
			return (x & y) ^ (~x & z);
		}
		
		inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
		{
			return (x & y) ^ (x & z) ^ (y & z);
		}
		
		inline uint32_t sigma0(uint32_t x)
		{
			return rotright(x, 2) ^ rotright(x, 13) ^ rotright(x, 22);
		}
		
		inline uint32_t sigma1(uint32_t x)
		{
			return rotright(x, 6) ^ rotright(x, 11) ^ rotright(x, 25);
		}
		
		inline uint32_t s0(uint32_t x)
		{
			return rotright(x, 7) ^ rotright(x, 18) ^ (x >> 3);
		}

		inline uint32_t s1(uint32_t x)
		{
			return rotright(x, 17) ^ rotright(x, 19) ^ (x >> 10);
		}
		
		inline void cycle(const uint32_t* w, std::size_t round, 
						  uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, 
						  uint32_t& e, uint32_t& f, uint32_t& g, uint32_t& h)
		{
			uint32_t t1 = h + sigma1(e) + ch(e,f,g) + constants::k[round] + w[round];
			uint32_t t2 = sigma0(a) + maj(a,b,c);
			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		
		void do_rounds(const uint32_t*w, uint32_t* hash, std::size_t round_count)
		{
			uint32_t a = hash[0];
			uint32_t b = hash[1];
			uint32_t c = hash[2];
			uint32_t d = hash[3];
			uint32_t e = hash[4];
			uint32_t f = hash[5];
			uint32_t g = hash[6];
			uint32_t h = hash[7];
			
			for (std::size_t round=0; round < round_count; ++round)
			{
				details::cycle(w, round, a, b, c, d, e, f, g, h);
			}

			hash[0] += a;
			hash[1] += b;
			hash[2] += c;
			hash[3] += d;
			hash[4] += e;
			hash[5] += f;
			hash[6] += g;
			hash[7] += h;
		}
		
		void prepare(const unsigned char* in, std::size_t length, std::size_t full_length, uint32_t* w)
		{
			if (length < 64)
			{
				memcpy(w, in, length);
				
				unsigned char* wc = reinterpret_cast<unsigned char*>(w);
				wc[length] = 0x80;
				for (std::size_t i=length+1; i<56; ++i)
				{
					wc[i] = 0;
				}
				uint64_t blen = full_length * 8;
				w[14] = static_cast<uint32_t>(blen >> 32);
				w[15] = static_cast<uint32_t>(blen);
				for (std::size_t i=0; i<14; ++i)
				{
					w[i] = BSWAP32(w[i]);
				}
			}
			else
			{
				const uint32_t* in32 = reinterpret_cast<const uint32_t*>(in);
				for (std::size_t i=0; i<16; ++i)
				{
					w[i] = BSWAP32(in32[i]);
				}
			}
			
			for (std::size_t r = 16; r < 64; ++r)
			{
				w[r] = s1(w[r-2]) + w[r-7] + s0(w[r-15]) + w[r-16];
			}
		}
	}
	
	void sha256(const unsigned char* in, std::size_t length, std::vector<unsigned char>& output)
	{
		const std::size_t chunk_size = 512 / 8;
		const std::size_t round_count = 64;

		// 1. prepare output
		std::vector<unsigned char>(32).swap(output);
		
		// 2. initialize
		uint32_t hash[8] = 
		{ 
			constants::h0, 
			constants::h1, 
			constants::h2, 
			constants::h3, 
			constants::h4, 
			constants::h5, 
			constants::h6, 
			constants::h7 
		};
		
		uint32_t w[round_count] = { 0 };
		std::size_t chunk;
		
		// 3. first part of the algorithm: all chunks except the last one
		for (chunk = 0; chunk + chunk_size < length; chunk += chunk_size)
		{
			details::prepare(in + chunk, chunk_size, length, w);
			details::do_rounds(w, hash, round_count);
		}
		
		// 4. final round
		details::prepare(in + chunk, length - chunk, length, w);
		details::do_rounds(w, hash, round_count);

		uint32_t* out = reinterpret_cast<uint32_t*>(&output.front());
		for (std::size_t i=0; i<8; ++i)
		{
			out[i] = BSWAP32(hash[i]);
		}
	}
	
} }
