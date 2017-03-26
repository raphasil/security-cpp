/*   
   Raphael Nascimento raphasil@gmail.com
*/

#include <vector>

#include "encoder_base64.h"

namespace ph { namespace encoder {
	
	const std::string base64::m_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
	
	void base64::encode_to(const base64::input_type& in, base64::output_type& out)
	{
	
		typedef input_type::const_iterator v_iterator;
		
		unsigned char char_array_3[3] = { 0 };
		unsigned char char_array_4[4] = { 0 };
		int i = 0;
		
		out.clear();
		
		v_iterator first = in.begin();

		while (first != in.end()) 
		{
			char_array_3[i++] = *first++;
			if (i == 3)
			{
				char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
				char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
				char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
				char_array_4[3] = char_array_3[2] & 0x3f;

				for(int j = 0; (j <4) ; j++)
				{
					out += m_chars[char_array_4[j]];
				}
				i = 0;
			}
		}

		if (i)
		{
			std::fill(char_array_3 + i, char_array_3 + 3, '\0');

			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (int j = 0; (j < i + 1); j++)
			{
				out += m_chars[char_array_4[j]];
			}
			while((i++ < 3))
			{
				out += '=';
			}
		}
	}

	void base64::decode_to(const base64::output_type& datain, base64::input_type& dataout) 
	{
		unsigned char char_array_4[4] = { 0 };
		unsigned char char_array_3[3] = { 0 };
		int i = 0;
		
		dataout.clear();

		std::string::const_iterator it = datain.begin();
		
		while (it != datain.end() && *it != '=' && is_base64(*it))
		{
			char_array_4[i++] = *it++;
			
			if (i == 4) 
			{
				for (int j = 0; j < 4; j++)
				{
					char_array_4[j] = m_chars.find(char_array_4[j]);
				}
				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (int j = 0; j < 3; j++)
				{
					dataout.push_back(char_array_3[j]);
				}
				i = 0;
			}
		}
		
		if (i) 
		{
			std::fill(char_array_4 + i, char_array_4 + 4, 0);

			for (int j = 0; j <4; j++)
			{
				char_array_4[j] = m_chars.find(char_array_4[j]);
			}
			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (int j = 0; (j < i - 1); j++) 
			{
				dataout.push_back(char_array_3[j]);
			}
		}
	}

} }