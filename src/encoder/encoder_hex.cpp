/*   
   Raphael Nascimento raphasil@gmail.com
*/

#include "encoder_hex.h"

namespace ph { namespace encoder {
	
	void hex::encode_to(const hex::input_type& in, hex::output_type& out)
	{
		out.clear();
		out.resize(in.size() * 2);
		
		for (std::size_t i=0; i<in.size(); ++i)
		{
			char_to_hex(in[i], out[i*2+0], out[i*2+1]);
		}
	}
	
	void hex::decode_to(const hex::output_type& in, hex::input_type& out)
	{
		out.clear();
		out.resize(in.length() / 2);
		
		for (std::size_t i=0; i<out.size(); ++i)
		{
			out[i] = hex_to_char(in[i*2+0], in[i*2+1]);
		}
	}
	
} }