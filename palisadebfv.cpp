/***************************************/
/* PALISADE BFV*/
/* Parts of code borrowed from:        */
/* demo-simple-exmple.cpp              */
/* final Equation e = x2 + yz */
/***************************************/

#include "palisade.h"
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
using namespace std;
using namespace lbcrypto;

void print(Plaintext v, int length)
{

    int print_size = 20;
    int end_size = 2;

    cout << endl;
    cout << "    [";

    for (int i = 0; i < print_size; i++)
    {
        cout << setw(3) << right << v->GetPackedValue()[i] << ",";
    }

    cout << setw(3) << " ...,";

    for (int i = length - end_size; i < length; i++)
    {
        cout << setw(3) << v->GetPackedValue()[i] << ((i != length - 1) ? "," : " ]\n");
    }
    
    cout << endl;
}

int main()
{
	//Check to see if BFVrns is available
	#ifdef NO_QUADMATH
	cout << "This program cannot run due to BFVrns not being available for this architecture." 
	exit(0);
	#endif
	srand(time(NULL));

	/*****Set up the CryptoContext*****/
	clock_t cc_clock;
	cc_clock = clock();
	//Parameter Selection based on standard parameters from HE standardization workshop
  int plaintextModulus = 536903681;
	double sigma = 3.2;
	SecurityLevel securityLevel = HEStd_128_classic;
	uint32_t depth = 2;


	//Create the cryptoContext with the desired parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(plaintextModulus, securityLevel, sigma, 0, depth, 0, OPTIMIZED);

	//Enable wanted functions
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	cc_clock = clock() - cc_clock;

	/*****Generate Keys*****/ 
	clock_t key_clock;
	key_clock = clock();

	//Create the container for the public key   
	LPKeyPair<DCRTPoly> keyPair;

	//Generate the keyPair
	keyPair = cryptoContext->KeyGen();

	//Generate the relinearization key
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	key_clock = clock() - key_clock;

	/*****Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

	//Create and encode the plaintext vectors and variables
	int N = 2760; 
	vector<int64_t> first_x; 
	vector<int64_t> second_y; 
	vector<int64_t> third_z;   

	for(int i = 0; i < N; i++)
	{
		int64_t a = rand() % 25;
		first_x.push_back(a);

		int64_t b = rand() % 50;
		second_y.push_back(b);

		int64_t c = rand() % 30;
		third_z.push_back(c);
	}

	Plaintext plain_first_x = cryptoContext->MakePackedPlaintext(first_x);
	Plaintext plain_second_y= cryptoContext->MakePackedPlaintext(second_y);
	Plaintext plain_third_z = cryptoContext->MakePackedPlaintext(third_z);

	//Encrypt the encodings
	auto enc_first_x= cryptoContext->Encrypt(keyPair.publicKey, plain_first_x);
	auto enc_second_y= cryptoContext->Encrypt(keyPair.publicKey, plain_second_y);
	auto enc_third_z = cryptoContext->Encrypt(keyPair.publicKey, plain_third_z);

	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
 	clock_t eval_clock;
	eval_clock = clock();

	auto enc_x_add_z = cryptoContext->EvalAdd(enc_first_x, enc_third_z);                  //x+z
	auto enc_final_e = cryptoContext->EvalMult(enc_second_y, enc_x_add_z);			//y(x+z)

	eval_clock = clock() - eval_clock;

	/*****Decryption*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_final_e;
	cryptoContext->Decrypt(keyPair.secretKey, enc_final_e, &plain_final_e);

	dec_clock = clock() - dec_clock;

	/*****Print*****/
	cout << "Solving Equation for" << N << " instances. "<< endl << endl;

	cout << "Value_X: " << endl;
	print(plain_first_x, N);

	cout << "Value_Y: " << endl;
	print(plain_second_y, N);

	cout << "Value_Z: " << endl;
	print(plain_third_z, N);

	cout << " Final Equation: " << endl;
	print(plain_final_e, N);

	cout << "Times:" <<endl;
	cout << "Parameter Generation : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation       : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption           : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (e = y(x+z))  : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption               : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
