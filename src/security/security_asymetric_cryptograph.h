/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef security_asymetric_cryptograph_h
#define security_asymetric_cryptograph_h

#include <algorithm>

namespace ph { namespace security {

	namespace details
	{
		class public_key_generator;
		class asymetric_key_generator;
	}
	
	template <class Cipher>
	class public_asymetric_key
	{
		public:
			typedef Cipher cipher_type;
			typedef typename cipher_type::public_storage_type public_storage_type;
			typedef typename cipher_type::input_type input_type;
			typedef typename cipher_type::output_type output_type;
			
		private:
			friend class details::public_key_generator;
			
			public_storage_type m_storage;

			public_asymetric_key(const public_storage_type& storage)
			: m_storage(storage)
			{ }
			
		public:
			public_asymetric_key()
			: m_storage()
			{ }
			
			public_asymetric_key(const public_asymetric_key& other)
			: m_storage(other.m_storage)
			{ }
			
			~public_asymetric_key()
			{ }
			
			public_asymetric_key& operator=(const public_asymetric_key& other)
			{
				public_asymetric_key(other).swap(*this);
				return *this;
			}
			
			void swap(public_asymetric_key& other)
			{
				std::swap(m_storage, other.m_storage);
			}

			const public_storage_type& storage() const
			{ return m_storage; }

			bool save_to(output_type& output) const
			{
				return cipher_type::save_public_key(m_storage, output);
			}
			
			template <class Encoder>
			bool save_to(typename Encoder::output_type& output, Encoder encoder) const
			{
				output_type real_output;
				bool r = save_to(real_output);
				encoder.encode_to(real_output, output);
				return r;
			}
			
			// might throw security::invalid_key_spec
			bool load_from(const input_type& input)
			{
				return cipher_type::load_public_key(input, m_storage);
			}

			// might throw security::invalid_key_spec
			template <class Encoder>
			bool load_from(const typename Encoder::output_type& input, Encoder encoder)
			{
				input_type real_input;
				encoder.decode_to(input, real_input);
				return load_from(real_input);
			}
	};
	
	template <class Cipher>
	class asymetric_key
	{
		public:
			typedef Cipher cipher_type;
			typedef typename cipher_type::storage_type storage_type;
			typedef typename cipher_type::public_key_type public_key_type;
			typedef typename cipher_type::public_storage_type public_storage_type;
			typedef typename cipher_type::input_type input_type;
			typedef typename cipher_type::output_type output_type;

		private:
			friend class details::asymetric_key_generator;
			
			storage_type m_storage;
			
			asymetric_key(const storage_type& storage)
			: m_storage(storage)
			{ }
			
		public:
			asymetric_key() 
			: m_storage() 
			{ }
			
			asymetric_key(const asymetric_key& other)
			: m_storage(other.m_storage)
			{ }
			
			~asymetric_key()
			{ }
			
			asymetric_key& operator=(const asymetric_key& other)
			{
				asymetric_key(other).swap(*this);
				return *this;
			}
			
			void swap(asymetric_key& other) throw()
			{
				std::swap(m_storage, other.m_storage);
			}
			
			const storage_type& storage() const
			{ return m_storage; }
			
			public_key_type get_public_key() const;
			
			bool save_to(output_type& prvout, output_type& pubout) const
			{
				return cipher_type::save_keys(m_storage, prvout, pubout);
			}
			
			template <class Encoder>
			bool save_to(typename Encoder::output_type& prvout, typename Encoder::output_type& pubout, Encoder encoder) const
			{
				output_type real_prvout;
				output_type real_pubout;
				bool r = save_to(real_prvout, real_pubout);
				encoder.encode_to(real_prvout, prvout);
				encoder.encode_to(real_pubout, pubout);
				return r;
			}
			
			// might throw security::invalid_key_spec
			bool load_from(const input_type& prvin, const input_type& pubin)
			{
				return cipher_type::load_keys(prvin, pubin, m_storage);
			}

			// might throw security::invalid_key_spec
			template <class Encoder>
			bool load_from(const typename Encoder::output_type& prvin, const typename Encoder::output_type& pubin, Encoder encoder)
			{
				input_type real_prvin;
				input_type real_pubin;
				encoder.decode_to(prvin, real_prvin);
				encoder.decode_to(pubin, real_pubin);
				return load_from(real_prvin, real_pubin);
			}
	};
	
	template <class Cipher, class Rng = typename Cipher::rng_type>
	class asymetric_cryptograph
	{
		public:
			typedef Cipher cipher_type;
			typedef Rng rng_type;
			typedef typename cipher_type::key_type key_type;
			typedef typename cipher_type::public_key_type public_key_type;
			typedef typename rng_type::seed_type rng_seed_type;
			typedef typename cipher_type::input_type input_type;
			typedef typename cipher_type::output_type output_type;
		
		private:
			rng_type m_rng;
			
		public:
			asymetric_cryptograph(const rng_type& rng = rng_type())
			: m_rng(rng)
			{ }
			
			asymetric_cryptograph(const asymetric_cryptograph& other)
			: m_rng(other.m_rng)
			{ }
			
			~asymetric_cryptograph()
			{ }
			
			asymetric_cryptograph& operator=(const asymetric_cryptograph& other)
			{
				asymetric_cryptograph(other).swap(*this);
				return *this;
			}
			
			void swap(asymetric_cryptograph& other) throw()
			{
				std::swap(m_rng, other.m_rng);
			}

			key_type generate_key();
			
			key_type generate_key(rng_seed_type seed)
			{
				m_rng.reseed(seed);
				return generate_key();
			}
			
			bool encrypt_public(const public_key_type& key, const input_type& input, output_type& output) const
			{
				return cipher_type::encrypt_public(key.storage(), input, output);
			}
			
			bool decrypt_private(const key_type& key, const output_type& input, input_type& output) const
			{
				return cipher_type::decrypt_private(key.storage(), input, output);
			}

			template <class Encoder>
			bool encrypt_public(const public_key_type& key, const input_type& input, typename Encoder::output_type& output, Encoder encoder) const
			{
				output_type real_output;
				if (encrypt_public(key, input, real_output))
				{
					encoder.encode_to(real_output, output);
				}
				return false;
			}
			
			template <class Encoder>
			bool decrypt_private(const key_type& key, const typename Encoder::output_type& input, input_type& output, Encoder encoder) const
			{
				input_type real_input;
				encoder.decode_to(input, real_input);
				return decrypt_private(key, real_input, output);
			}

			bool encrypt_private(const key_type& key, const input_type& input, output_type& output) const
			{
				return cipher_type::encrypt_private(key.storage(), input, output);
			}
			
			bool decrypt_public(const public_key_type& key, const output_type& input, input_type& output) const
			{
				return cipher_type::decrypt_public(key.storage(), input, output);
			}

			template <class Encoder>
			bool encrypt_private(const key_type& key, const input_type& input, typename Encoder::output_type& output, Encoder encoder) const
			{
				output_type real_output;
				if (encrypt_private(key, input, real_output))
				{
					encoder.encode_to(real_output, output);
				}
				return false;
			}
			
			template <class Encoder>
			bool decrypt_public(const public_key_type& key, const typename Encoder::output_type& input, input_type& output, Encoder encoder) const
			{
				input_type real_input;
				encoder.decode_to(input, real_input);
				return decrypt_public(key, real_input, output);
			}
	};
	
	namespace details 
	{
		struct asymetric_key_generator
		{
			template <class Cipher>
			static typename Cipher::key_type 
			generate(const typename Cipher::storage_type& storage)
			{
				typedef typename Cipher::key_type key_type;
				return key_type(storage);
			}
		};

		struct public_key_generator
		{
			template <class Cipher>
			static typename Cipher::public_key_type 
			generate(const typename Cipher::public_storage_type& storage)
			{
				typedef typename Cipher::public_key_type public_key_type;
				return public_key_type(storage);
			}
		};
	}
	
	template <class Cipher>
	typename Cipher::public_key_type 
	asymetric_key<Cipher>::get_public_key() const
	{
		using namespace details;
		
		return public_key_generator::generate<cipher_type>(public_storage_type(m_storage));
	}
	
	template <class Cipher, class Rng>
	typename asymetric_cryptograph<Cipher,Rng>::key_type 
	asymetric_cryptograph<Cipher,Rng>::generate_key()
	{
		using namespace details;
		
		return asymetric_key_generator::generate<Cipher>(Cipher::generate_storage(m_rng));
	}
	
} }

#endif // security_asymetric_cryptograph_h