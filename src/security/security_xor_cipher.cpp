/*   
   Raphael Nascimento raphasil@gmail.com
*/

#include <openssl/blowfish.h>
#include "security_xor_cipher.h"

namespace ph { namespace security {

	xor_cipher::storage_type xor_cipher::generate_storage(const xor_cipher::sequence_type& rseq)
	{
		return storage_type(rseq);
	}

	void xor_cipher::save_key(const xor_cipher::storage_type& storage, xor_cipher::output_type& output)
	{
		std::vector<unsigned char>(storage.bits()).swap(output);
	}
	
	bool xor_cipher::load_key(const xor_cipher::input_type& input, xor_cipher::storage_type& storage)
	{
		storage = storage_type(input);
		return true;
	}

	bool xor_cipher::encrypt(const xor_cipher::storage_type& storage, const xor_cipher::input_type& input, xor_cipher::output_type& output)
	{
		output.resize(input.size());
		
		const std::vector<unsigned char>& bits = storage.bits();
		
		for (std::size_t i=0; i<input.size(); ++i)
		{
			std::size_t x = i % bits.size();
			output[i] = input[i] ^ bits[x];
		}
		
		return true;
	}
	
	bool xor_cipher::decrypt(const xor_cipher::storage_type& storage, const xor_cipher::output_type& input, xor_cipher::input_type& output)
	{
		output.resize(input.size());
		
		const std::vector<unsigned char>& bits = storage.bits();
		
		for (std::size_t i=0; i<input.size(); ++i)
		{
			std::size_t x = i % bits.size();
			output[i] = input[i] ^ bits[x];
		}
		
		return true;
	}
} }