# security-cpp

## namespace ph::encoder

This namespace contains the definition of encoders, i.e. objects that can transform an input into an
output in a specific format.

The following classes are defined in this namespace :

- *basic_encoder<I,O>* : base class for all encoders
- *base64* : Base64 encoder / decoder
- *hex* : Hex (base 16) encoder / decoder

### Class encoder::basic_encoder<I,O>

This class is the base class for all encoders. It defines the following members :
- *basic_encoder<I,O> ::input_type* - This is a type alias on the template parameter I
- *basic_encoder<I,O> ::output_type* - This is a type alias on the template parameter O.


### Class encoder::base64

This class inherits basic_encoder<I,O>, with I = std ::vector<unsigned char> and O = std ::string.
Furthermore, the class defines the following services :
- void encode_to(const input_type& in, output_type& out) (method)
- void decode_to(const output_type& in, input_type& out) (method)

#### Example

`

string txt = "Hello world";
string output;
vector<unsigned char> input(a.begin(), a.end());
vector<unsigned char> revinput;

encoder::base64().encode_to(input, output);
encoder::base64().decode_to(output, revinput);

`

### Class encoder::hex
This class inherits basic_encoder<I,O>, with I = std ::vector<unsigned char> and O = std ::string.
Furthermore, the class defines the following services :
- void encode_to(const input_type& in, output_type& out) (method)
- void decode_to(const output_type& in, input_type& out) (method)


#### Example

`

string txt = "Hello world";
string output;
vector<unsigned char> input(a.begin(), a.end());
vector<unsigned char> revinput;

encoder::hex().encode_to(input, output);
encoder::hex().decode_to(output, revinput);

`

## namespace ph::security

This namespace contains class definition used to perform encryption and decryption of data.
Encrypted data can be encoded to a Base64 buffer (thanks to the encoding classes in namespace
ph::encoder) in order to display it, or to send it through a text stream (socket, file,...).

### The namespace contains the following template classes
- symetric_cryptograph<C,RNG>
- symetric_key<C>
- asymetric_cryptograph<C,RNG>
- asymetric_key<C>
- public_asymetric_key<C>

### These classes are instatiated to produce the following classes
- blowfish_cryptograph = symetric_cryptograph<bf_cipher, default_rng>
- blowfish_key = symetric_key<bf_cipher>
- xor_cryptograph = symetric_cryptograph<xor_cipher, xor_rng>
- xor_key = symetric_key<xor_cipher>
- rsa_cryptograph = asymetric_cryptograph<rsa_cipher, default_rng>
- rsa_key = asymetric_key<rsa_cipher>
- rsa_public_key = public_asymetric_key<rsa_cipher>

