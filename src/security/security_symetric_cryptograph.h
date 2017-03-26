/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef security_symetric_cryptography_h
#define security_symetric_cryptography_h

#include <exception>
#include <algorithm>
#include <string>

namespace ph { namespace security {

	namespace details 
	{
		class symetric_key_generator;
	}

	class invalid_key_spec : public std::exception
	{
		private:
			std::string m_what;
		
		public:
			invalid_key_spec()
			: m_what()
			{ }
			
			~invalid_key_spec() throw()
			{ }
			
			invalid_key_spec(const std::string& w) 
			: m_what(w)
			{ }
			
			virtual const char* what() const throw()
			{ return m_what.c_str(); }
	};

	template <class Cipher>
	class symetric_key
	{
		public:
			// cipher_type shall be the type of a symetric cipher
			typedef Cipher cipher_type;
			
			// storage_type shall be default constructibe, copy constructible 
			// and copiable. 
			typedef typename cipher_type::storage_type storage_type;
			
			// input and output type shall be iterable
			typedef typename cipher_type::input_type input_type;
			typedef typename cipher_type::output_type output_type;
			
		private:
			storage_type m_storage;
			
			symetric_key(const storage_type& storage)
			: m_storage(storage)
			{ }
			
			friend class details::symetric_key_generator;
			
		public:
			symetric_key()
			: m_storage()
			{ }
			
			symetric_key(const symetric_key& other)
			: m_storage(other.m_storage)
			{ }
			
			~symetric_key()
			{ }
			
			symetric_key& operator=(const symetric_key& other)
			{
				symetric_key(other.m_storage).swap(*this);
				return *this;
			}
			
			void swap(symetric_key& other) throw ()
			{
				std::swap(other.m_storage, m_storage);
			}
			
			void save_to(output_type& output) const
			{
				cipher_type::save_key(m_storage, output);
			}
			
			template <class Encoder>
			void save_to(typename Encoder::output_type& output, Encoder encoder) const
			{
				output_type real_output;
				save_to(real_output);
				encoder.encode_to(real_output, output);
			}
			
			// might throw security::invalid_key_spec
			bool load_from(const input_type& input)
			{
				return cipher_type::load_key(input, m_storage);
			}

			// might throw security::invalid_key_spec
			template <class Encoder>
			bool load_from(const typename Encoder::output_type& input, Encoder encoder)
			{
				input_type real_input;
				encoder.decode_to(input, real_input);
				return load_from(real_input);
			}
			
			const storage_type& storage() const 
			{ return m_storage; }
			
			std::size_t length() const
			{ return m_storage.length(); }
	};
	
	// Rng shall be default-constructible, copy-constructible and
	// copiable. 
	template <class Cipher, class Rng = typename Cipher::rng_type>
	class symetric_cryptograph
	{
		public:
			typedef Cipher cipher_type;
			typedef Rng rng_type;
			typedef typename cipher_type::key_type key_type;
			typedef typename rng_type::seed_type rng_seed_type;
			typedef typename cipher_type::input_type input_type;
			typedef typename cipher_type::output_type output_type;
		
		private:
			rng_type		m_rng;
		
		public:
			symetric_cryptograph(const rng_type& rng = rng_type())
			: m_rng(rng)
			{ }
			
			symetric_cryptograph(const symetric_cryptograph& other)
			: m_rng(other.m_rng)
			{ }
			
			~symetric_cryptograph()
			{ }
			
			symetric_cryptograph& operator=(const symetric_cryptograph& other)
			{
				cryptograph(other).swap(*this);
				return *this;
			}
			
			void swap(symetric_cryptograph& other) throw ()
			{
				std::swap(m_rng, other.m_rng);
			}
			
			key_type generate_key();
			
			key_type generate_key(rng_seed_type seed)
			{
				m_rng.reseed(seed);
				return generate_key();
			}
			
			bool encrypt(const key_type& key, const input_type& input, output_type& output) const
			{
				return cipher_type::encrypt(key.storage(), input, output);
			}
			
			bool decrypt(const key_type& key, const output_type& input, input_type& output) const
			{
				return cipher_type::decrypt(key.storage(), input, output);
			}

			template <class Encoder>
			bool encrypt(const key_type& key, const input_type& input, typename Encoder::output_type& output, Encoder encoder) const
			{
				output_type real_output;
				if (encrypt(key, input, real_output))
				{
					encoder.encode_to(real_output, output);
				}
				return false;
			}
			
			template <class Encoder>
			bool decrypt(const key_type& key, const typename Encoder::output_type& input, input_type& output, Encoder encoder) const
			{
				input_type real_input;
				encoder.decode_to(input, real_input);
				return decrypt(key, real_input, output);
			}
	};
	
	namespace details 
	{
		struct symetric_key_generator
		{
			template <class Cipher>
			static typename Cipher::key_type generate(const typename Cipher::storage_type& storage)
			{
				typedef typename Cipher::key_type key_type;
				return key_type(storage);
			}
		};
	}
	
	template <class Cipher, class Rng>
	typename symetric_cryptograph<Cipher,Rng>::key_type 
	symetric_cryptograph<Cipher,Rng>::generate_key()
	{
		using namespace details;
		
		return symetric_key_generator::generate<Cipher>(Cipher::generate_storage(m_rng));
	}
	
} }

#endif // security_symetric_cryptography_h