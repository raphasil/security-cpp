/*   
   Raphael Nascimento raphasil@gmail.com
*/

#include "security_rsa_cipher.h"
#include <openssl/rsa.h>

namespace ph { namespace security {
	
	rsa_storage::rsa_storage(const rsa_storage& other)
	: m_rsa(other.m_rsa)
	{
		if (m_rsa) 
		{ 
			RSA_up_ref(m_rsa); 
		}
	}
	
	rsa_storage& rsa_storage::operator=(const rsa_storage& other)
	{
		m_rsa = other.m_rsa;
		if (m_rsa) 
		{ 
			RSA_up_ref(m_rsa); 
		}
		return *this;
	}
	
	rsa_storage::~rsa_storage()
	{
		if (m_rsa) 
		{ 
			RSA_free(m_rsa); 
		}
	}
	
	rsa_cipher::storage_type rsa_cipher::generate_storage()
	{
		RSA* rsa = RSA_generate_key(2048, 17, NULL, NULL);
		return storage_type(rsa);
	}

	bool rsa_cipher::save_public_key(const rsa_cipher::storage_type& storage, rsa_cipher::output_type& output)
	{
		unsigned char *out = NULL;
		int out_length;
		out_length = i2d_RSAPublicKey(storage.rsa(), &out);
		if (out_length > 0)
		{
			output.clear();
			output.reserve(out_length);
			output.insert(output.end(), out, out + out_length);
			OPENSSL_free(out);
			return true;
		}
		return false;
	}
	
	bool rsa_cipher::save_private_key(const rsa_cipher::storage_type& storage, rsa_cipher::output_type& output)
	{
		unsigned char *out = NULL;
		int out_length;
		out_length = i2d_RSAPrivateKey(storage.rsa(), &out);
		if (out_length > 0)
		{
			output.clear();
			output.reserve(out_length);
			output.insert(output.end(), out, out + out_length);
			OPENSSL_free(out);
			return true;
		}
		return false;
	}
	
	bool rsa_cipher::load_public_key(const rsa_cipher::input_type& input, rsa_cipher::storage_type& storage)
	{
		RSA* rsa = NULL;
		if (storage.rsa())
		{
			rsa = storage.rsa();
		}
		else
		{
			rsa = RSA_new();
		}
		const unsigned char* inptr = &input.front();
		RSA* result = d2i_RSAPublicKey(&rsa, &inptr, (long)input.size());
		if (result)
		{
			if (!storage.rsa())
			{
				storage_type(rsa).swap(storage);
			}
			return true;
		}
		return false;
	}
	
	bool rsa_cipher::load_private_key(const rsa_cipher::input_type& input, rsa_cipher::storage_type& storage)
	{
		RSA* rsa = NULL;
		if (storage.rsa())
		{
			rsa = storage.rsa();
		}
		else
		{
			rsa = RSA_new();
		}
		const unsigned char* inptr = &input.front();
		RSA* result = d2i_RSAPrivateKey(&rsa, &inptr, (long)input.size());
		if (result)
		{
			if (!storage.rsa())
			{
				storage_type(rsa).swap(storage);
			}
			return true;
		}
		return false;
	}
	
	bool rsa_cipher::encrypt_public(const rsa_cipher::public_storage_type& storage, const rsa_cipher::input_type& input, rsa_cipher::output_type& output)
	{
		RSA* rsa = const_cast<RSA*>(storage.rsa());
		
		output.clear();
		
		std::size_t rsa_size = RSA_size(rsa);
		std::size_t max_length = std::max(rsa_size / 2, rsa_size - 64);
		std::size_t processed_length = 0;
		
		output_type tempout(rsa_size * 2);
		
		unsigned char* from = const_cast<unsigned char*>(&input.front());
		
		while (processed_length < input.size())
		{
			std::size_t chunk_length = max_length;
			if (input.size() - processed_length < chunk_length)
			{
					chunk_length = input.size() - processed_length;
			}
			int outlen = RSA_public_encrypt(chunk_length, from + processed_length, &tempout.front(), rsa, RSA_PKCS1_PADDING);
			if (outlen < 0) return false;
			processed_length += outlen;
			output.insert(output.end(), tempout.begin(), tempout.begin() + outlen);
		}
		
		return true;
	}
	
	bool rsa_cipher::decrypt_public(const rsa_cipher::public_storage_type& storage, const rsa_cipher::output_type& input, rsa_cipher::input_type& output)
	{
		RSA* rsa = const_cast<RSA*>(storage.rsa());
		
		std::size_t rsa_size = RSA_size(rsa);
		std::size_t processed_length = 0;
		
		input_type tempout(rsa_size * 2);
		
		unsigned char* from = const_cast<unsigned char*>(&input.front());
		
		while (processed_length < input.size())
		{
			std::size_t chunk_length = rsa_size;
			if (input.size() - processed_length < chunk_length)
			{
					chunk_length = input.size() - processed_length;
			}
			int outlen = RSA_public_decrypt(chunk_length, from + processed_length, &tempout.front(), rsa, RSA_PKCS1_PADDING);
			if (outlen < 0) return false;
			processed_length += chunk_length;
			output.insert(output.end(), tempout.begin(), tempout.begin() + outlen);
		}
		
		return true;
	}
	
	bool rsa_cipher::encrypt_private(const rsa_cipher::storage_type& storage, const rsa_cipher::input_type& input, rsa_cipher::output_type& output)
	{
		RSA* rsa = const_cast<RSA*>(storage.rsa());
		
		output.clear();
		
		std::size_t rsa_size = RSA_size(rsa);
		std::size_t max_length = std::max(rsa_size / 2, rsa_size - 64);
		std::size_t processed_length = 0;
		
		output_type tempout(rsa_size * 2);
		
		unsigned char* from = const_cast<unsigned char*>(&input.front());
		
		while (processed_length < input.size())
		{
			std::size_t chunk_length = max_length;
			if (input.size() - processed_length < chunk_length)
			{
					chunk_length = input.size() - processed_length;
			}
			int outlen = RSA_private_encrypt(chunk_length, from + processed_length, &tempout.front(), rsa, RSA_PKCS1_PADDING);
			if (outlen < 0) return false;
			processed_length += outlen;
			output.insert(output.end(), tempout.begin(), tempout.begin() + outlen);
		}
		
		return true;
	}
	
	bool rsa_cipher::decrypt_private(const rsa_cipher::storage_type& storage, const rsa_cipher::output_type& input, rsa_cipher::input_type& output)
	{
		RSA* rsa = const_cast<RSA*>(storage.rsa());
		
		std::size_t rsa_size = RSA_size(rsa);
		std::size_t processed_length = 0;
		
		input_type tempout(rsa_size * 2);
		
		unsigned char* from = const_cast<unsigned char*>(&input.front());
		
		while (processed_length < input.size())
		{
			std::size_t chunk_length = rsa_size;
			if (input.size() - processed_length < chunk_length)
			{
					chunk_length = input.size() - processed_length;
			}
			int outlen = RSA_private_decrypt(chunk_length, from + processed_length, &tempout.front(), rsa, RSA_PKCS1_PADDING);
			if (outlen < 0) return false;
			processed_length += chunk_length;
			output.insert(output.end(), tempout.begin(), tempout.begin() + outlen);
		}
		
		return true;
	}
} }
