/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef security_sha_digest_h
#define security_sha_digest_h

#include <iterator>
#include <algorithm>
#include <vector>

namespace ph { namespace security {

	void sha256(const unsigned char* in, std::size_t length, std::vector<unsigned char>& output);

	namespace details {

		
		template <class InIt, class IteratorTag>
		struct sha256_helper
		{
			static void execute(InIt first, InIt last, std::vector<unsigned char>& output, const IteratorTag&)
			{
				typedef typename std::iterator_traits<InIt>::value_type value_type;
				
				std::vector<value_type> v(first, last);
				
				std::size_t byte_count = v.size() * sizeof(value_type);
				unsigned char* from = reinterpret_cast<unsigned char*>(&v.front());
				
				sha256(from, byte_count, output); 
			}
		};
		
		template <class InIt>
		struct sha256_helper<InIt, std::random_access_iterator_tag>
		{
			static void execute(InIt first, InIt last, std::vector<unsigned char>& output, const std::random_access_iterator_tag&)
			{
				typedef typename std::iterator_traits<InIt>::value_type value_type;
				typedef typename std::iterator_traits<InIt>::difference_type diff_type;
				
				diff_type count = std::distance(first, last);
				std::size_t byte_count = count * sizeof(value_type);
				unsigned char* from = reinterpret_cast<unsigned char*>(&(*first));
				
				sha256(from, byte_count, output); 
			}
		};
		
	}
	
	template  <class InIt>
	void sha256(InIt first, InIt last, std::vector<unsigned char>& output)
	{
		typedef typename std::iterator_traits<InIt>::iterator_category iterator_tag;
		
		details::sha256_helper<InIt,iterator_tag>::execute(first, last, output, iterator_tag());
	}
	
	template  <class InIt, class Encoder>
	void sha256(InIt first, InIt last, typename Encoder::output_type& output, Encoder encoder)
	{
		std::vector<unsigned char> real_output;
		sha256(first, last, real_output);
		encoder.encode_to(real_output, output);
	}

	template <class Encoder>
	void sha256(const unsigned char* in, std::size_t length, typename Encoder::output_type& output, Encoder encoder)
	{
		std::vector<unsigned char> real_output;
		sha256(in, length, real_output);
		encoder.encode_to(real_output, output);
	}
	
} }

#endif // security_sha_digest_h