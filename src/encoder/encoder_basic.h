/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef encoder_basic_h
#define encoder_basic_h

namespace ph { namespace encoder {
	
	template <class Input, class Output>
	struct basic_encoder
	{
		typedef Input input_type;
		typedef Output output_type;
	};
	
} }

#endif // encoder_basic_h