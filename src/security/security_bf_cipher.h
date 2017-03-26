/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef security_bf_cipher_h
#define security_bf_cipher_h

#include <vector>
#include "security_rng.h"
#include "security_symetric_cryptograph.h"

namespace ph { namespace security {

	class bf_cipher;
	
	class bf_storage
	{
		public:
			static const unsigned int key_length = 32; // 256 bits
		
		private:
			friend class bf_cipher;
			
			typedef std::vector<unsigned char> bits_type;

		private:
			bits_type m_bits;
			
		private:
			bf_storage(const bits_type& bits)
			: m_bits(bits)
			{ }
			
			const bits_type& bits() const
			{
				return m_bits;
			}
			
		public:
			bf_storage() : m_bits() 
			{ }
			
			bf_storage(const bf_storage& other) 
			: m_bits(other.m_bits)
			{ }
			
			~bf_storage()
			{ }
			
			bf_storage& operator=(const bf_storage& other)
			{
				std::vector<unsigned char>(other.m_bits).swap(m_bits);
				return *this;
			}
			
			std::size_t length() const { return m_bits.size(); }
	};
	
	class bf_cipher
	{
		private:
			bf_cipher();
			bf_cipher(const bf_cipher&);
			bf_cipher& operator=(const bf_cipher&);
			~bf_cipher();
		
		public:
			typedef default_rng rng_type;
			typedef std::vector<unsigned char> input_type;
			typedef std::vector<unsigned char> output_type;
			typedef bf_storage storage_type;
			typedef symetric_key<bf_cipher> key_type;

		private:
			typedef std::vector<unsigned char> sequence_type;
			
			static storage_type generate_storage(const sequence_type& rseq);
			
		public:
			template <class Rng>
			static storage_type generate_storage(Rng rng)
			{
				sequence_type rseq(storage_type::key_length);
				
				rng.build_sequence(&rseq.front(), rseq.size());
				return generate_storage(rseq);
			}
			
			static bool load_key(const input_type& input, storage_type& storage);
			static void save_key(const storage_type& storage, output_type& output);
			static bool encrypt(const storage_type& storage, const input_type& input, output_type& output);
			static bool decrypt(const storage_type& storage, const output_type& input, input_type& output);
	};
	
	typedef symetric_cryptograph<bf_cipher> blowfish_cryptograph;
	typedef symetric_key<bf_cipher> blowfish_key;
	
} }

#endif //  security_bf_cipher_h