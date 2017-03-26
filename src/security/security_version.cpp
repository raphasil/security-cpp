/*   
   Raphael Nascimento raphasil@gmail.com
*/

#include <sstream>
#include "security_version.h"

namespace ph { namespace security {

	std::string version_string() 
	{
		std::stringstream stream;
		
		unsigned int major, minor, build;
		
		get_version(major, minor, build);
		
		stream << major << "." << minor << "." << build;
		return stream.str();
	}

} }
