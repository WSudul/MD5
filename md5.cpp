#include "stdafx.h"
#include "md5.h"

//zdefiniowanie przesuniec bitowych
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

//funkcja zwracajaca kod md5
std::string md5_hash(const std::string str);


inline uint32_t MD5::F(uint32_t X, uint32_t Y, uint32_t Z) {
	return (X&Y) | (~(X)&Z);
}

inline uint32_t MD5::G(uint32_t X, uint32_t Y, uint32_t Z) {
	return (X&Z) | (Y&(~Z));
}

inline uint32_t MD5::H(uint32_t X, uint32_t Y, uint32_t Z) {
	return X^Y^Z;
}

inline uint32_t MD5::I(uint32_t X, uint32_t Y, uint32_t Z) {
	return Y ^ (X | (~Z));
}

// obrot cykliczny 32-bitowego slowa w lewo
inline uint32_t MD5::rotate_left(uint32_t x, int n) {
	return (x << n) | (x >> (32 - n));
}


inline void MD5::FF(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t T) {
	a = rotate_left(a + F(b, c, d) + x + T, s) + b;
}

inline void MD5::GG(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t T) {
	a = rotate_left(a + G(b, c, d) + x + T, s) + b;
}

inline void MD5::HH(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t T) {
	a = rotate_left(a + H(b, c, d) + x + T, s) + b;
}

inline void MD5::II(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t T) {
	a = rotate_left(a + I(b, c, d) + x + T, s) + b;
}


// konstruktor przetrwarzajacy string na hash
MD5::MD5(const std::string &text)
{
	init();
	//std::cout << "init\n";
	update((uint8_t*)text.c_str(), text.length());
	//std::cout << "finalize\n";
	finalize();
}

//inicjalizacja parametrow
void MD5::init()
{
	finalized = false;

	//zerowanie licznika 64-bitowego
	counter[0] = 0;
	counter[1] = 0;

	//zapisanie wartosci stalych potrzebnych do inicjalizacji algorytmu
	status_arr[0] = 0x67452301;
	status_arr[1] = 0xefcdab89;
	status_arr[2] = 0x98badcfe;
	status_arr[3] = 0x10325476;
}


// dekodowanie bloku danych wejsciowych input z 8bit na 32 bit. Na jednym elemecie output zapisane zostana 4 elementy input
void MD5::decode(uint32_t output[], const uint8_t input[], uint32_t len)
{
	//std::cout << "Funkcja decode" << std::endl;
	//liczniki powinny miec zakres conajmniej typu zmiennej len
	uint32_t i = 0;
	for (uint32_t j = 0; j < len;j += 4)
	{
		output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) |
			(((uint32_t)input[j + 2]) << 16) | (((uint32_t)input[j + 3]) << 24);
		i++;
	}
}


// kodowanie bloku wejsciowego z 32bit na 8bit; Na jednym elemecie input zapisane zostana 4 elementy output
void MD5::encode(uint8_t output[], const uint32_t input[], uint32_t len)
{
	uint32_t i=0;
	//std::cout << "Funkcja encode" << std::endl;
	//liczniki powinny miec zakres conajmniej typu zmiennej len
	for (uint32_t j = 0; j < len;j += 4)
	{
		output[j] = input[i] & 0xff;
		output[j + 1] = (input[i] >> 8) & 0xff;
		output[j + 2] = (input[i] >> 16) & 0xff;
		output[j + 3] = (input[i] >> 24) & 0xff;
		i++;
	}
}


// funkcja wykonujaca algorytm MD5 na pojedynczym bloku danych
void MD5::transform(const uint8_t block[64])
{
	//std::cout << "Funkcja transfrom" << std::endl;
	uint32_t a, b, c, d;
	uint32_t x[16];
	//przypsanie zmiennym aktualnych wartosci stanu
	a = status_arr[0];
	b = status_arr[1];
	c = status_arr[2];
	d = status_arr[3];

	decode(x, block, 64);


	//Wykonanie 64 iteracji - 4 Cykle po 16
	/*
		Ostatni argument funkcji FF,GG,HH i II jest
		wartoœci¹ obliczana jako
		floor(232 * abs(sin(i + 1)))
		Ominiete zostalo wykonanie w petli for(i=0,i<64,i++)
		w celu przyspieszenia wykonania glownej czessci algorytmu
		
	*/

	// Cykl 1 - FF, zmiana x -> i++ gdzie 0<=i<16;
	FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
	FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
	FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
	FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
	FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
	FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
	FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
	FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
	FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
	FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	//Cykl 2 - GG, zmiana x -> (5*i+1) % 16; gdzie 16=<i<32
	GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
	GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
	GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	//Cykl 3 - HH, zmiana x -> (3*i+5) % 16; gdzie 32=<i<48
	HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
	HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
	HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

	//Cykl 4 - II, zmiana x -> (7*i) % 16; gdzie 48=<i<64
	II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
	II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

	//dodawanie transformacji do obecnego stanu
	status_arr[0] += a;
	status_arr[1] += b;
	status_arr[2] += c;
	status_arr[3] += d;

	// Zerowanie  informacji - forma zabezpieczenia algorytmu
	memset(x, 0, sizeof(x));
}


// dzielenie wiadomosci na bloki, dodanie paddingu, wykonanie algorytmu i aktualizacja wyniku
void MD5::update(const uint8_t *input, uint32_t length)
{
	//std::cout << "Funkcja update"<< std::endl;

	uint32_t index = counter[0] / 8 % 64;
	//std::cout << "index=" << index << std::endl;
	//aktualizacja liczby bitow,
	if ((counter[0] += (length << 3)) < (length << 3))
		counter[1]++;

	counter[1] += (length >> 29);

	// liczba bajtow potrzeban do wypelnienia bufora
	uint32_t firstpart = 64 - index;

	uint32_t i;
	//std::cout << "firstpart=" << firstpart << std::endl;
	//wykonywanie tranfsformacji
	if (length >= firstpart)
	{
		//kopiowanie bloku wejsciowego do bufora
		 memcpy(&buffer[index], input, firstpart);
		 //std::copy(input, input + firstpart, &buffer[index]); //C4996 Error  code - teoretycznie mozna uzyc, ale funkcja nie umie zweryfikowac poprawnosci danych

		transform(buffer);

		// transformowanie bloku 64 bajtowch (512 bit)
		for (i = firstpart; i + 64 <= length; i += 64)
			transform(&input[i]);

		index = 0;
	}
	else
		i = 0;

	//std::cout << "i=" << i <<"\tlength="<<length<<"\tindex"<<index<< std::endl;
	// buforwanie reszty bloku wiadomosci (dla niepelnego) dla dalszej obrobki
	memcpy(&buffer[index], &input[i], length - i);

}



//konczenie algorytmu, sprzatanie(zerowanie) tablic i przepisanie wyniku do tablicy wyjsciowej msg_digest
MD5& MD5::finalize()
{
	//padding - rozmiar 64x8 bit =512 bit <- max rozmiar jaki moze przyjac
	static uint8_t padding[64] = 
	{//0x80 = 0b1000 0000 <- Nalezy zgodnie z algorytmem dolaczyc binarna jedynke
		0x80 
	}; // Reszta zostanie zinicjalizowana jako 0x00

	if (!finalized) 
	{
		
		uint8_t bits[8];
		uint32_t index;
		uint32_t pad_Len;

		// zapisanie liczby bitow do bits[8]
		encode(bits, counter, 8);

		
		index = counter[0] / 8 % 64;
		
		//ustalenie dlugosci pad_Len (max 64 bit)
		if (index < 56)
			pad_Len = 56 - index;
		else
			pad_Len = 120 - index;

		//dodanie paddingu i wykonanie aktualiacji
		update(padding, pad_Len);

		update(bits, 8);

		// zakodowanie stanu tablicy state do tablicy wyjsciowej msg_digest
		encode(msg_digest, status_arr, 16);

		// Zerowanie informacji
		// Memset - szybkie i proste inicjalizowanie kontenera 
		memset(buffer, 0, sizeof buffer);
		memset(counter, 0, sizeof counter);

		finalized = true;
	}

	return *this;
}



// reprezentacja w postaci hexadecymalnej
std::string MD5::hexdigest() const
{
	if (!finalized)
		return "";

	std::stringstream ss;
	ss << std::setfill('0');
	for(int i = 0; i < 16 ; ++i)
	{
		ss << std::setw(2) <<std::hex<< (unsigned int)msg_digest[i];
	};
	return std::string(ss.str());
}


// reprezentacja w postaci dziesietnej jako 16 8-bitowych slow
std::string MD5::decdigest() const
{
	std::stringstream ss;
	ss << std::setfill('0');
	for (int i = 0; i < 16; ++i)
		ss << std::setw(3) << std::dec << (unsigned int)msg_digest[i] << " ";

	return std::string(ss.str());
}


//funkcja zwracajaca 32-bitowy hash
std::string md5_hash(const std::string str)
{
	MD5 md5 = MD5(str);

	return md5.hexdigest();
}


int main(int argc, char *argv[])
{
	int x;
	std::string Temp;// = md5("The quick brown fox jumps over the lazy dog");
	//std::string Temp2 = "JtxamZ7DQHBKqFBEHYuOj5tpceMVf6TsJrGsp7MRlc8R6HJCj8zvEx6DJ2veTxLNhriWX0DL5WkQuZx54ozeQCngyB05yiMUFu13aPVhYxcZEnwW5YX2uyAgch8poDXX5qxSc3ycLqbOzmIYZfysJ6a2Y3EYK8oraiD63Xq2guCuIpJY3zKRt0yG2CJf7ArLNe2HQNKjZLCuMDAvlEi6HMuDQhb6S4ZmYWl18a2jWrRnkgh1qn1fg0rkDH9cK9DNnPRO2ggQ5Npfac9h4LCwcrhYgnvvJtDB6eTPZmIW0DZ5iucT2wao4ciQ6Fuea5OG1ayLuCfC4Zsa3YJo2rCPJvpZbFpBZMlHrvcz8KI1aunVyhUov1w7xPgLFGVCisjnKO8umbIjAnbjTarKBG3FPHe8r9OizH3yShqUpOrjBTo00t6wGB934F4G1xrUso13rasiRuXoWxknVty3iSDVWZ";
	//"Yolo!Thelongeststringicouldcomeupwithisreallynotgoingtoworkherebecauseitwillbetoobigformetocomprehendotherwise_illjusttrytomakeitupsomehowKEKKEKEKEKEKEEKEKEKEEK_@32412fasfas";
	std::string Temp2 = "abc123ef";
	//for (int i = 0; i < 15; i++)
	//	Temp2.append(Temp2);

	//std::cout << Temp2 << std::endl;
	//std::cout << Temp2.length() << std::endl;
	
	std::fstream plik;
	plik.open("plik.txt", std::ios::out);
	clock_t t1;
	Temp.append(Temp2);
	for (int i = 0; i < 20; i++)
	{
		
		Temp.append(Temp);
		//std::cout << "String i=" << i << std::endl;
		t1 = clock();
		std::string Test=md5_hash(Temp);
		t1 = clock() - t1;
		plik <<"Czas: "<< float(t1) / CLOCKS_PER_SEC<<"\n";
		plik << "Dlugosc: "<<Temp.length() << "\n" <<"Hash: "<< Test << "\n";
		
	}

	/*char text[33] = "sgogzlpgakh7y0mm7ny03tn26meree8w";

	for (int i = 32; i < 127; i++)
	{
		std::cout << i<< std::endl;
		for (int j = 0; j < 33; j++)
		{
			text[j] = i;
			plik << md5_hash(text) << "\n";
			
		}
	}*/


	//plik << Temp2;
	//plik << "\n";
	////std::cout << Temp.c_str() << std::endl;
	//std::cout << md5_hash("The quick brown fox jumps over the lazy dog") << std::endl;
	//plik << md5(Temp2);
	//MD5 new_obj("The quick brown fox jumps over the lazy dog");
	//std::cout << new_obj.hexdigest() << std::endl;
	//std::cout << new_obj.decdigest();
	std::cin >> x;
	return 0;
}