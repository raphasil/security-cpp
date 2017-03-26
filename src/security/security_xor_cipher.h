/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef security_xor_cipher_h
#define security_xor_cipher_h

#include "security_rng.h"
#include "security_symetric_cryptograph.h"

namespace ph { namespace security {
	
	class xor_cipher;
	
	class xor_storage
	{
		public:
			static const unsigned int key_length = 64;
		
		private:
			friend class xor_cipher;
			
			typedef std::vector<unsigned char> bits_type;

		private:
			bits_type m_bits;
			
		private:
			xor_storage(const bits_type& bits)
			: m_bits(bits)
			{ }
			
			const bits_type& bits() const
			{
				return m_bits;
			}
			
		public:
			xor_storage() : m_bits() 
			{ }
			
			xor_storage(const xor_storage& other) 
			: m_bits(other.m_bits)
			{ }
			
			~xor_storage()
			{ }
			
			xor_storage& operator=(const xor_storage& other)
			{
				std::vector<unsigned char>(other.m_bits).swap(m_bits);
				return *this;
			}
			
			std::size_t length() const { return m_bits.size(); }
	};
	
	class xor_cipher
	{
		private:
			xor_cipher();
			xor_cipher(const xor_cipher&);
			xor_cipher& operator=(const xor_cipher&);
			~xor_cipher();
		
		public:
			typedef xor_rng rng_type;
			typedef std::vector<unsigned char> input_type;
			typedef std::vector<unsigned char> output_type;
			typedef xor_storage storage_type;
			typedef symetric_key<xor_cipher> key_type;

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
	
	typedef symetric_cryptograph<xor_cipher> xor_cryptograph;
	typedef symetric_key<xor_cipher> xor_key;
	
} }

#endif // security_xor_cipher_h