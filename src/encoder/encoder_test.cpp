/*   
   Raphael Nascimento raphasil@gmail.com
*/

#include "encoder_base64.h"
#include "encoder_hex.h"

#include <vector>
#include <algorithm>
#include <string>
#include <iostream>

int main()
{
	using namespace ph;
	
	unsigned char test_1[] = "testing my own library...";
	
	std::cout << "source : " << test_1 << std::endl;
	std::cout << std::string(40, '-') << std::endl;
	
	std::vector<unsigned char> input;
	
	input.resize(sizeof(test_1)-1);
	std::copy(test_1, test_1 + sizeof(test_1) - 1, input.begin());
	
	std::string output;
	std::vector<unsigned char> revinput;

	encoder::hex().encode_to(input, output);
	encoder::hex().decode_to(output, revinput);
	
	std::cout << "correct: 74657374696e67206d79206f776e206c6962726172792e2e2e" << std::endl;
	std::cout << "is     : " << output << std::endl;
	std::cout << "decode : " << std::boolalpha << (revinput == input) << std::endl;
	
	std::cout << std::string(40, '-') << std::endl;

	encoder::base64().encode_to(input, output);
	encoder::base64().decode_to(output, revinput);
	
	std::cout << "correct: dGVzdGluZyBteSBvd24gbGlicmFyeS4uLg==" << std::endl;
	std::cout << "is     : " << output << std::endl;
	std::cout << "decode : " << std::boolalpha << (revinput == input) << std::endl;
}