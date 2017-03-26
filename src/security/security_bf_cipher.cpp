/*   
   Raphael Nascimento raphasil@gmail.com
*/

#include <openssl/blowfish.h>
#include "security_bf_cipher.h"

namespace ph { namespace security {

	bf_cipher::storage_type bf_cipher::generate_storage(const bf_cipher::sequence_type& rseq)
	{
		return storage_type(rseq);
	}

	void bf_cipher::save_key(const bf_cipher::storage_type& storage, bf_cipher::output_type& output)
	{
		std::vector<unsigned char>(storage.bits()).swap(output);
	}
	
	bool bf_cipher::load_key(const bf_cipher::input_type& input, bf_cipher::storage_type& storage)
	{
		storage = storage_type(input);
		return true;
	}

	bool bf_cipher::encrypt(const bf_cipher::storage_type& storage, const bf_cipher::input_type& input, bf_cipher::output_type& output)
	{
		int 				num = 0;
		BF_KEY 				schedule;
		unsigned char 		ivec[8] = { 0 };
		
		// 1. prepare the cipher
		const std::vector<unsigned char>& bits = storage.bits();
		BF_set_key(&schedule, bits.size(), &bits.front());
		
		// 2. encrypt
		output.resize(input.size());
		BF_cfb64_encrypt(&input.front(), &output.front(), output.size(), &schedule, ivec, &num, BF_ENCRYPT);
		
		return true;
	}
	
	bool bf_cipher::decrypt(const bf_cipher::storage_type& storage, const bf_cipher::output_type& input, bf_cipher::input_type& output)
	{
		int 				num = 0;
		BF_KEY 				schedule;
		unsigned char 		ivec[8] = { 0 };

		// 1. prepare the cipher
		const std::vector<unsigned char>& bits = storage.bits();
		BF_set_key(&schedule, bits.size(), &bits.front());

		// 2. encrypt
		output.resize(input.size());
		BF_cfb64_encrypt(&input.front(), &output.front(), output.size(), &schedule, ivec, &num, BF_DECRYPT);

		return true;
	}
	
} }