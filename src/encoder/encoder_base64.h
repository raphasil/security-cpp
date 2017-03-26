/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef encoder_base64_h
#define encoder_base64_h

#include <string>
#include <vector>
#include <cctype>

#include "encoder_basic.h"

namespace ph { namespace encoder {

	class base64 
	: public basic_encoder<std::vector<unsigned char>, std::string>
	{
		private:
			static const std::string m_chars;
		
		private:
			bool is_base64(unsigned char c) 
			{
				return (std::isalnum(c) || (c == '+') || (c == '/'));
			}
		
		public:
			void encode_to(const input_type& in, output_type& out);
			void decode_to(const output_type& in, input_type& out);
	};

} }

#endif // encoder_base64_h