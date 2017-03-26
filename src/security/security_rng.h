/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef security_rng_h
#define security_rng_h

#include <vector>
#include <string>
#include <exception>

namespace ph { namespace security {

	class not_enough_data : public std::exception
	{
		private:
			std::string m_what;
		
		public:
			not_enough_data()
			: m_what()
			{ }
			
			~not_enough_data() throw()
			{ }
			
			not_enough_data(const std::string& w) 
			: m_what(w)
			{ }
			
			virtual const char* what() const throw()
			{ return m_what.c_str(); }
	};

	class default_rng
	{
		public:
			typedef std::vector<unsigned char> seed_type;
			
		public:
			default_rng();
			default_rng(const default_rng& other);
			default_rng(const seed_type& seed);
			~default_rng();
			
			default_rng& operator=(const default_rng& other);
			
			void reseed(const seed_type& seed);
			void build_sequence(unsigned char* seq, unsigned int seqsize);
	};
	
	// A very simple XOR key generator
	class xor_rng
	{
		public:
			typedef std::string seed_type;
			
		private:
			seed_type m_content;
			
		public:
			xor_rng()
			{ }
			xor_rng(const xor_rng& other)
			: m_content(other.m_content)
			{ }
			xor_rng(const seed_type& seed)
			{
				reseed(seed);
			}
			~xor_rng()
			{ }
			
			xor_rng& operator=(const xor_rng& other)
			{
				seed_type(other.m_content).swap(m_content);
				return *this;
			}
			
			void reseed(const seed_type& seed)
			{
				seed_type(seed).swap(m_content);
			}
			
			void build_sequence(unsigned char* seq, unsigned int seqsize)
			{
				if (m_content.empty())
				{
					throw not_enough_data("XOR rng need a seed to work");
				}
				
				std::string content(m_content);
				while (content.length() < seqsize)
				{
					content += m_content;
				}
				std::copy(content.begin(), content.begin() + seqsize, seq);
			}
	};
	
} }

#endif // security_rng_h