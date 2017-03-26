/*   
   Raphael Nascimento raphasil@gmail.com
*/

#include <string>
#include <iostream>
#include <iomanip>
#include <vector>
#include <list>
#include <tr1/cstdint>
#include "security_symetric_cryptograph.h"
#include "security_asymetric_cryptograph.h"
#include "security_bf_cipher.h"
#include "security_xor_cipher.h"
#include "security_rsa_cipher.h"
#include "security_sha_digest.h"
#include "security_version.h"
#include "encoder_base64.h"
#include "encoder_hex.h"

void test_bf_cipher()
{
	std::cout << "Blowfish cipher (symetric)" << std::endl;
	
	using namespace ph;
	using namespace ph::security;
	
	blowfish_cryptograph 	cryptograph;
	blowfish_key 			key;
	
	key = cryptograph.generate_key();
	
	std::string 			b64key;
	
	key.save_to(b64key, encoder::base64());
	std::cout << std::string(80, '-') << std::endl;
	std::cout << "key length: " << key.length() << std::endl;
	std::cout << "base64(Kbf) = " << b64key << std::endl;

	blowfish_key 			other_key;
	std::string 			b64other;
	
	other_key.load_from(b64key, encoder::base64());
	other_key.save_to(b64other, encoder::base64());
	
	blowfish_key 			hex_key;
	std::string 			hother;
	std::string 			hother2;

	key.save_to(hother, encoder::hex());

	std::cout << "hex(Kbf) = " << hother << std::endl;

	hex_key.load_from(hother, encoder::hex());
	hex_key.save_to(hother2, encoder::base64());
	
	std::cout << "load+save shall produce the same value: " << std::boolalpha << (b64key == b64other) << std::endl;
	std::cout << "load+save(hex) shall produce the same value: " << std::boolalpha << (b64key == hother2) << std::endl;
	
	std::string 			input("this is a source string that I want to encrypt");
	std::string 			b64output;
	
	cryptograph.encrypt(key, blowfish_cryptograph::input_type(input.begin(), input.end()), b64output, encoder::base64());
	
	std::cout << std::string(80, '-') << std::endl;
	std::cout << "1/ TESTING ENCRYPTION - f() == base64(bfencrypt(Kbf,in))" << std::endl;
	std::cout << "input  = " << input << std::endl;
	std::cout << "output = " << b64output << std::endl;
	
	blowfish_cryptograph::output_type output;
	cryptograph.decrypt(key, b64output, output, encoder::base64());
	
	std::cout << std::string(80, '-') << std::endl;
	std::cout << "2/ TESTING DECRYPTION - f() == bfdecrypt(Kbf,unbase64(in))" << std::endl;
	std::cout << "input  = " << b64output << std::endl;
	std::cout << "output = " << std::string(output.begin(), output.end()) << std::endl;

	std::cout << std::string(80, '-') << std::endl;
	std::cout << std::endl;
}

void test_xor_cipher()
{
	std::cout << "XOR cipher (symetric)" << std::endl;
	
	using namespace ph;
	using namespace ph::security;
	
	xor_cryptograph 	cryptograph;
	xor_key 			key;
	xor_rng::seed_type	seed("!ThIs Is My kEy SeEd!");
	
	
	key = cryptograph.generate_key(seed);
	
	std::string 			b64key;
	
	key.save_to(b64key, encoder::base64());
	std::cout << std::string(80, '-') << std::endl;
	std::cout << "using seed = " << seed << std::endl;
	std::cout << "key length: " << key.length() << std::endl;
	std::cout << "base64(Kxor) = " << b64key << std::endl;

	blowfish_key 			other_key;
	std::string 			b64other;
	
	other_key.load_from(b64key, encoder::base64());
	other_key.save_to(b64other, encoder::base64());
	
	std::cout << "load+save shall produce the same value: " << std::boolalpha << (b64key == b64other) << std::endl;
	
	std::string 			input("this is a source string that I want to encrypt");
	std::string 			b64output;
	
	cryptograph.encrypt(key, blowfish_cryptograph::input_type(input.begin(), input.end()), b64output, encoder::base64());
	
	std::cout << std::string(80, '-') << std::endl;
	std::cout << "1/ TESTING ENCRYPTION - f() == base64(xorencrypt(Kxor,in))" << std::endl;
	std::cout << "input  = " << input << std::endl;
	std::cout << "output = " << b64output << std::endl;
	
	blowfish_cryptograph::output_type output;
	cryptograph.decrypt(key, b64output, output, encoder::base64());
	
	std::cout << std::string(80, '-') << std::endl;
	std::cout << "2/ TESTING DECRYPTION - f() == xordecrypt(Kxor,unbase64(in))" << std::endl;
	std::cout << "input  = " << b64output << std::endl;
	std::cout << "output = " << std::string(output.begin(), output.end()) << std::endl;

	std::cout << std::string(80, '-') << std::endl;
	std::cout << std::endl;
}

void test_rsa_cipher()
{
	std::cout << "RSA cipher (asymetric)" << std::endl;
	
	using namespace ph;
	using namespace ph::security;
	
	rsa_cryptograph 		cryptograph;
	rsa_key					key;
	rsa_public_key			public_key;
	
	key = cryptograph.generate_key();
	public_key = key.get_public_key();
	
	std::cout << std::string(80, '-') << std::endl;
	
	std::string 			b64prv;
	std::string				b64pub;
	std::string				b64cpub;
	
	key.save_to(b64prv, b64pub, encoder::base64());
	public_key.save_to(b64cpub, encoder::base64());
	
	std::cout << "base64(Kprv) = " << b64prv << std::endl << std::endl;
	std::cout << "base64(Kpub) = " << b64pub << std::endl << std::endl;
	std::cout << "base64(copy(Kpub)) = " << b64cpub << std::endl;

	std::cout << std::string(80, '-') << std::endl;
	std::cout << "load keys..." << std::endl;
	
	rsa_key					ckey;
	std::string 			b64other_prv;
	std::string				b64other_pub;
	
	ckey.load_from(b64prv, b64pub, encoder::base64());
	ckey.save_to(b64other_prv, b64other_pub, encoder::base64());
	std::cout << "load+save on full key: " << std::boolalpha << (b64prv == b64other_prv && b64pub == b64other_pub) << std::endl;
	
	rsa_public_key			cpublic_key;
	std::string				b64other_cpub;
	
	cpublic_key.load_from(b64cpub, encoder::base64());
	cpublic_key.save_to(b64other_cpub, encoder::base64());
	
	std::cout << "load+save on public key alone: " << std::boolalpha << (b64cpub == b64other_cpub) << std::endl;
	
	std::string 					src("I wanna to encrypt this string using the RSA encryption algorithms (both public and private)");
	std::string 					b64enc;
	rsa_cryptograph::input_type 	decout;
	
	std::cout << std::string(80, '-') << std::endl;
	std::cout << "1/ ENCRYPT PUBLIC" << std::endl;
	cryptograph.encrypt_public(public_key, rsa_cryptograph::input_type(src.begin(), src.end()), b64enc, encoder::base64());
	std::cout << "input  = " << src << std::endl;
	std::cout << "output = " << b64enc << std::endl;

	std::cout << std::string(80, '-') << std::endl;
	std::cout << "2/ DECRYPT PRIVATE" << std::endl;
	decout.clear();
	cryptograph.decrypt_private(key, b64enc, decout, encoder::base64());
	std::cout << "input  = " << b64enc << std::endl;
	std::cout << "output = " << std::string(decout.begin(), decout.end()) << std::endl;

	std::cout << std::string(80, '-') << std::endl;
	std::cout << "3/ ENCRYPT PRIVATE" << std::endl;
	cryptograph.encrypt_private(key, rsa_cryptograph::input_type(src.begin(), src.end()), b64enc, encoder::base64());
	std::cout << "input  = " << src << std::endl;
	std::cout << "output = " << b64enc << std::endl;

	std::cout << std::string(80, '-') << std::endl;
	std::cout << "4/ DECRYPT PUBLIC" << std::endl;
	decout.clear();
	cryptograph.decrypt_public(public_key, b64enc, decout, encoder::base64());
	std::cout << "input  = " << b64enc << std::endl;
	std::cout << "output = " << std::string(decout.begin(), decout.end()) << std::endl;
	
	std::cout << std::string(80, '-') << std::endl;
	std::cout << std::endl;
}

void test_sha_digest_1()
{
	using namespace ph;

	std::string sinput("ceci est un test, ceci est un test, ceci est un test");
	std::vector<char> vinput(sinput.begin(), sinput.end());
	std::list<char> linput(sinput.begin(), sinput.end());
	
	std::string hr_si;
	std::string hr_vi1;
	std::string hr_vi2;
	std::string hr_li;
	
	security::sha256(sinput.begin(), sinput.end(), hr_si, encoder::hex());
	security::sha256((unsigned char*)&vinput.front(), vinput.size(), hr_vi1, encoder::hex());
	security::sha256(vinput.begin(), vinput.end(), hr_vi2, encoder::hex());
	security::sha256(linput.begin(), linput.end(), hr_li, encoder::hex());
	
	std::cout << "sha(" << sinput << ") = " << std::endl;
	std::cout << "others: " << std::boolalpha << (hr_si == hr_vi1);
	std::cout << ", " << (hr_vi1 == hr_vi1) << ", " << (hr_li == hr_vi1) << std::endl;
	std::cout << "SI      = " << hr_si << std::endl;
	std::cout << "Vi1     = " << hr_vi1 << std::endl;
	std::cout << "vi2     = " << hr_vi2 << std::endl;
	std::cout << "LI      = " << hr_li << std::endl; 
	std::cout << "shall be: 4d51a5b2e00f229cfa941241a37b3dd1c6c55b58693c5d9ec87d8d3f739fbc5d" << std::endl;

	std::cout << std::string(80, '-') << std::endl;
	std::cout << std::endl;
}

void test_sha_digest_2()
{
	using namespace ph;

	std::string sinput("yg+SyLwYdVweepK5CKh7DQdUj1ZB2nczzycbF32MMkYkavzJRna8CbH07QIEQ6oyEGSiRzRXaMJX/SjkurtS+gHYrzzIG0uUcxcYThnxK27xKE59vQhYfx8KGg/QseaG0pcrQTjusm4a+TE+ZW1/I6aoXWWcNmVDL+hnGVPKp9UPQplXtBYV+/R//W1LNDXvvk6726018dy9wPtP0w+3UhxlPtCmUqJkiBdDAa8nKl/PaqI/LEV9b8H5YolslSKvVFgCB7A1diL2T17NL11rCIV6bo6QWzocwlcCUuJsvjndeG0gwDpksjE4Mb4V0/PMCSHKf4FrrZd53RnKQH9T4w==");
	std::vector<char> vinput(sinput.begin(), sinput.end());
	std::list<char> linput(sinput.begin(), sinput.end());
	
	std::string hr_si;
	std::string hr_vi1;
	std::string hr_vi2;
	std::string hr_li;
	
	security::sha256(sinput.begin(), sinput.end(), hr_si, encoder::hex());
	security::sha256((unsigned char*)&vinput.front(), vinput.size(), hr_vi1, encoder::hex());
	security::sha256(vinput.begin(), vinput.end(), hr_vi2, encoder::hex());
	security::sha256(linput.begin(), linput.end(), hr_li, encoder::hex());
	
	std::cout << "sha(" << sinput << ") = " << std::endl;
	std::cout << "others: " << std::boolalpha << (hr_si == hr_vi1);
	std::cout << ", " << (hr_vi1 == hr_vi1) << ", " << (hr_li == hr_vi1) << std::endl;
	std::cout << "SI      = " << hr_si << std::endl;
	std::cout << "Vi1     = " << hr_vi1 << std::endl;
	std::cout << "vi2     = " << hr_vi2 << std::endl;
	std::cout << "LI      = " << hr_li << std::endl; 
	std::cout << "shall be: 617097036e3ba36934568f80837f8215326122c362cb0cb99f9c8443b3b1c65c" << std::endl;

	std::cout << std::string(80, '-') << std::endl;
	std::cout << std::endl;
}

void test_sha_digest_3()
{
	using namespace ph;

	std::string sinput;
	std::vector<char> vinput(sinput.begin(), sinput.end());
	std::list<char> linput(sinput.begin(), sinput.end());
	
	std::string hr_si;
	std::string hr_vi1;
	std::string hr_vi2;
	std::string hr_li;
	
	security::sha256(sinput.begin(), sinput.end(), hr_si, encoder::hex());
	security::sha256((unsigned char*)&vinput.front(), vinput.size(), hr_vi1, encoder::hex());
	security::sha256(vinput.begin(), vinput.end(), hr_vi2, encoder::hex());
	security::sha256(linput.begin(), linput.end(), hr_li, encoder::hex());
	
	std::cout << "sha(" << sinput << ") = " << std::endl;
	std::cout << "others: " << std::boolalpha << (hr_si == hr_vi1);
	std::cout << ", " << (hr_vi1 == hr_vi1) << ", " << (hr_li == hr_vi1) << std::endl;
	std::cout << "SI      = " << hr_si << std::endl;
	std::cout << "Vi1     = " << hr_vi1 << std::endl;
	std::cout << "vi2     = " << hr_vi2 << std::endl;
	std::cout << "LI      = " << hr_li << std::endl; 
	std::cout << "shall be: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" << std::endl;

	std::cout << std::string(80, '-') << std::endl;
	std::cout << std::endl;
}

int main()
{
	std::cout << std::string(80, '-') << std::endl;
	std::cout << "version = " << ph::security::version_string() << std::endl;
	std::cout << std::string(80, '-') << std::endl;
	std::cout << std::endl;
	
	test_bf_cipher();
	
	test_xor_cipher();
	
	test_rsa_cipher();
	
	test_sha_digest_1();
	test_sha_digest_2();
	test_sha_digest_3();
}
