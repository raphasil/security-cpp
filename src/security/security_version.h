/*   
   Raphael Nascimento raphasil@gmail.com
*/

#ifndef security_version_h
#define security_version_h

namespace ph { namespace security {
	
	inline void get_version(unsigned int& major, unsigned int& minor, unsigned int& build)
	{
		major = 0;
		minor = 2;
		build = 0;
	}
	
	std::string version_string();
	
} }

#endif // security_version_h
