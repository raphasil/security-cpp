/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef encoder_hex_h
#define encoder_hex_h

#include <vector>
#include <string>
#include "encoder_basic.h"

namespace ph { namespace encoder {
	
	class hex 
	: public basic_encoder<std::vector<unsigned char>, std::string>
	{ 
		private:
			void char_to_hex(unsigned char c, char& low, char& hi) throw();
			unsigned char hex_to_char(char low, char hi) throw();
		
		public:
			void encode_to(const input_type& in, output_type& out);
			void decode_to(const output_type& in, input_type& out);
	};
	
	inline void hex::char_to_hex(unsigned char c, char& hi, char& low) throw()
	{
		low = c & 0x0f;
		hi = (c >> 4) & 0x0f;
		
		low += (low >= 10 ? 'a' - 10 : '0');
		hi += (hi >= 10 ? 'a' - 10 : '0');
	}
	
	inline unsigned char hex::hex_to_char(char hi, char low) throw()
	{
		unsigned char r = 0;
		
		if (low >= 'a' && low <= 'f') r |= ((low - 'a' + 10) & 0x0f);
		else if (low >= 'A' && low <= 'F') r |= ((low - 'A' + 10) & 0x0f);
		else if (low >= '0' && low <= '9') r |= ((low - '0') & 0x0f);

		if (hi >= 'a' && hi <= 'f') r |= (((hi - 'a' + 10) & 0x0f) << 4);
		else if (hi >= 'A' && hi <= 'F') r |= (((hi - 'A' + 10) & 0x0f) << 4);
		else if (hi >= '0' && hi <= '9') r |= (((hi - '0') & 0x0f) << 4);
		
		return r;
	}

} }

#endif // encoder_hex_h