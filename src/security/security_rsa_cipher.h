/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef security_rsa_cipher_h
#define security_rsa_cipher_h

#include "security_asymetric_cryptograph.h"
#include "security_rng.h"

typedef struct rsa_st RSA;

namespace ph { namespace security {

	class rsa_storage
	{
		private:
			RSA* m_rsa;
			
			friend class rsa_cipher;
			
			RSA* rsa() { return m_rsa; }
			const RSA* rsa() const { return m_rsa; }
			
			void swap(rsa_storage& other)
			{
				std::swap(m_rsa, other.m_rsa);
			}
		
		public:
			rsa_storage()
			: m_rsa(NULL)
			{ }

			rsa_storage(RSA* rsa)
			: m_rsa(rsa)
			{ }
			
			rsa_storage(const rsa_storage& other);
			
			~rsa_storage();
			
			rsa_storage& operator=(const rsa_storage& other);
	};
	
	class rsa_cipher
	{
		private:
			rsa_cipher();
			rsa_cipher(const rsa_cipher&);
			~rsa_cipher();
			rsa_cipher& operator=(const rsa_cipher&);
			
		public:
			typedef rsa_storage storage_type;
			typedef rsa_storage public_storage_type;
			typedef asymetric_key<rsa_cipher> key_type;
			typedef public_asymetric_key<rsa_cipher> public_key_type;
			typedef default_rng rng_type;
			typedef std::vector<unsigned char> input_type;
			typedef std::vector<unsigned char> output_type;
			
		private:
			typedef std::vector<unsigned char> sequence_type;
			
			static storage_type generate_storage();
			
			static bool save_private_key(const storage_type& storage, output_type& output);
			static bool load_private_key(const input_type& input, storage_type& storage);
			
		public:
			template <class Rng>
			static storage_type generate_storage(Rng rng)
			{
				return generate_storage();
			}
			
			static bool save_public_key(const storage_type& storage, output_type& output);
			static bool load_public_key(const input_type& input, storage_type& storage);

			static bool save_keys(const storage_type& storage, output_type& prvout, output_type& pubout)
			{
				return (save_private_key(storage, prvout) && save_public_key(storage, pubout));
			}

			static bool load_keys(const input_type& prvin, const input_type& pubin, storage_type& storage)
			{
				if (load_public_key(pubin, storage))
				{
					return load_private_key(prvin, storage);
				}
				return false;
			}

			static bool encrypt_public(const public_storage_type& storage, const input_type& input, output_type& output);
			static bool decrypt_public(const public_storage_type& storage, const output_type& input, input_type& output);
			static bool encrypt_private(const storage_type& storage, const input_type& input, output_type& output);
			static bool decrypt_private(const storage_type& storage, const output_type& input, input_type& output);
	};
	
	typedef asymetric_cryptograph<rsa_cipher> rsa_cryptograph;
	typedef asymetric_cryptograph<rsa_cipher>::key_type rsa_key;
	typedef asymetric_cryptograph<rsa_cipher>::public_key_type rsa_public_key;
	
} }

#endif // security_rsa_cipher_h