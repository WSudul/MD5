#ifndef MD5_H
#define MD5_H

#include <cstring>
#include <iostream>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <string>
#include <fstream>
#include <cstdio>
#include <algorithm>


class MD5
{
public:



	MD5(const std::string& text);	//konstruktor
	std::string decdigest() const;	//zwracanie kodu w postaci 10
	std::string hexdigest() const; //zwracanie kodu w postaci 11
private:

	//funkcje zajmujace sie przetworzeniem danych
	void init(); 
	void update(const uint8_t *input, uint32_t length); 
	MD5& finalize();
	void transform(const uint8_t block[64]);
	void decode(uint32_t output[], const uint8_t input[], uint32_t len);
	void encode(uint8_t output[], const uint32_t input[], uint32_t len);

	
	bool finalized;	//flaga zakonczenia hashowania
	uint8_t buffer[64]; // bufor o rozmiarze 64x8 bit=512 bit, dla ostatniego bloku danych
	uint32_t counter[2];   // 64bitowy licznik w formie tablicy, format little Endian
	uint32_t status_arr[4];   // tablica przechowujaca dotychczasowe zshashowane wartosci
	uint8_t msg_digest[16]; // wynik koncowy (128-bitowy ciag)

	//funkcje logiczne operujace na 32 bitowych zmiennych
	static inline uint32_t F(uint32_t X, uint32_t Y, uint32_t Z);
	static inline uint32_t G(uint32_t X, uint32_t Y, uint32_t Z);
	static inline uint32_t H(uint32_t X, uint32_t Y, uint32_t Z);
	static inline uint32_t I(uint32_t X, uint32_t Y, uint32_t Z);
	static inline uint32_t rotate_left(uint32_t x, int n);

	//funkcje glownej czesci algorytmu
	static inline void FF(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t T);
	static inline void GG(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t T);
	static inline void HH(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t T);
	static inline void II(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t T);
};



#endif