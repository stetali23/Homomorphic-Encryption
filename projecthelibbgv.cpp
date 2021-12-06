/***************************************/
/* HElib BGV */
/* Parts of code borrowed from:        */
/* BGV_packed_arithmetic.cpp             */
/* final equation e = y(x+z)     */
/***************************************/
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <helib/helib.h>

using namespace std;
using namespace helib;

void print(vector<long> v, long length)
{

    int print_size = 20;
    int end_size = 2;

    cout << endl;
    cout << "    [";

    for (int i = 0; i < print_size; i++)
    {
        cout << setw(3) << right << v[i] << ",";
    }

    cout << setw(3) << " ...,";

    for (int i = length - end_size; i < length; i++)
    {
        cout << setw(3) << v[i] << ((i != length - 1) ? "," : " ]\n");
    }
    
    cout << endl;
}

int main()
{
	srand(time(NULL));
	/*****Set Parameters*****/
	clock_t cc_clock;
	cc_clock = clock();

	unsigned long p   = 55001;
	unsigned long m  = 32109;
	unsigned long bits = 300;
	unsigned long c = 2;
        unsigned long r = 1;

	//Generate context and add primes to chain
	 helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .bits(bits)
                               .c(c)
                               .build();
	//Context context(cyc_poly, prime_mod, 1);
	//buildModChain(context, bits_mod_chain, key_switch_col);
	// Print the context
  	context.printout();
 	 std::cout << std::endl;

  	// Print the security level
  	std::cout << "Security: " << context.securityLevel() << std::endl;

	cc_clock = clock() - cc_clock;

	//Key Generation
	clock_t key_clock;
	key_clock = clock();

	// Secret key management
  	std::cout << "Creating secret key..." << std::endl;
  	// Create a secret key associated with the context
  	helib::SecKey secret_key(context);
 	 // Generate the secret key
	  secret_key.GenSecKey();
 	 std::cout << "Generating key-switching matrices..." << std::endl;
 	 // Compute key-switching matrices that we need
	  helib::addSome1DMatrices(secret_key);

 	 // Public key management
  	// Set the secret key (upcast: SecKey is a subclass of PubKey)
 	 const helib::PubKey& public_key = secret_key;

	 // Get the EncryptedArray of the context
  	const helib::EncryptedArray& ea = context.getEA();

 	 // Get the number of slot (phi(m))
	  long nslots = ea.size();
	  std::cout << "Number of slots: " << nslots << std::endl;

	key_clock = clock() - key_clock;

	//Encryption
	clock_t enc_clock;
	enc_clock = clock();

	vector<long> first_x;
	vector<long> second_y;
	vector<long> third_z;

	for(int i = 0; i < nslots; i++)
	{
		int64_t a = rand() % 25;
		first_x.push_back(a);

		int64_t b = rand() % 50;
		second_y.push_back(b);

		int64_t c = rand() % 30;
		third_z.push_back(c);
	}

	Ctxt enc_first_x(public_key);
	Ctxt enc_second_y(public_key);
	Ctxt enc_third_z(public_key);
	Ctxt enc_final_e(public_key);
	ea.encrypt(enc_first_x, public_key, first_x);
	ea.encrypt(enc_second_y, public_key, second_y);
	ea.encrypt(enc_third_z, public_key, third_z);

	enc_clock = clock() - enc_clock;

	//Evaluation
	clock_t eval_clock;
	eval_clock = clock();

	enc_final_e += enc_first_x;
	enc_final_e += enc_third_z;
	enc_final_e *= enc_second_y;

	eval_clock = clock() - eval_clock;

	//Decrypt
	clock_t dec_clock;
	dec_clock = clock();

	vector<long> final_e;
	ea.decrypt(enc_final_e, secret_key, final_e);

	dec_clock = clock() - dec_clock;
	/*****Print*****/
	cout << "Solving the equation for " << nslots << " instances. "<< endl << endl;

	cout << "Value_X: " << endl;
	print(first_x, nslots);

	cout << "Value_Y: " << endl;
	print(second_y, nslots);

	cout << "Value_Z: " << endl;
	print(third_z, nslots);

	cout << "Final Equation: " << endl;
	print(final_e, nslots);

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (e = y(x+z)   ) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;

}
