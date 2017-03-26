/*   
   Raphael Nascimento raphasil@gmail.com
*/

#include <openssl/rand.h>
#include "security_rng.h"

namespace ph { namespace security {

	default_rng::default_rng()
	{ }
	
	default_rng::default_rng(const default_rng& other)
	{ }
	
	default_rng::default_rng(const default_rng::seed_type& seed)
	{
		reseed(seed);
	}
	
	default_rng::~default_rng()
	{ }
	
	default_rng& default_rng::operator=(const default_rng& other)
	{
		return *this;
	}
	
	void default_rng::reseed(const default_rng::seed_type& seed)
	{
		RAND_add(&seed.front(), seed.size(), seed.size() * 0.75);
	}
	
	void default_rng::build_sequence(unsigned char* seq, unsigned int seqsize)
	{
		if (!RAND_bytes(seq, seqsize))
		{
			throw not_enough_data("RNG entropy is too low to generate new random number");
		}
	}
	
} }