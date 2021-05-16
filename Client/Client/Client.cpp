#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <windows.h>
#include <CkCrypt2.h>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT "27015"
#define DEFAULT_BUFLEN 1024

struct addrinfo* result = NULL, * ptr = NULL, hints;  //addrinfo struktura inicializira spremenljivke v sockadrr strukturi

void error(int iResult, SOCKET clientSocket, std::string errmsg) { //Tako preverim �e je kak�na napaka

	if (iResult == SOCKET_ERROR) {
		std::cout << errmsg << WSAGetLastError() << "\n";
		closesocket(clientSocket);
		WSACleanup();
		exit(1);
	}
}

int main(int argc, char* argv[]) {
	WSADATA wsaData;
	int iResult;

	// Inicializacija Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		std::cout << "WSAStartup failed: " << iResult << "\n";
		return 1;
	}

	struct addrinfo* result = NULL, * ptr = NULL, hints;  //addrinfo struktura inicializira spremenljivke v sockadrr strukturi

	ZeroMemory(&hints, sizeof(hints)); //ker niso init se uporabi ta funkcija
	hints.ai_family = AF_UNSPEC; //ni specificirano, zato da lahko vra�a IPv4 in IPv6
	hints.ai_socktype = SOCK_STREAM; //specificira stream vti�nico
	hints.ai_protocol = IPPROTO_TCP; //specificira TCP protokol

	iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result); //v cmd moramo specificirat IP naslov stre�nika
	if (iResult != 0) {
		std::cout << "getaddrinfo failed: " << iResult << "\n";
		WSACleanup();
		return 1;
	}

	SOCKET connectSocket = INVALID_SOCKET; //vti�nica za povezavo

	ptr = result; //prvo poskusimo vspostaviti povezavo s prvim naslovom, ki ga vrne getaddrinfo

	connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

	if (connectSocket == INVALID_SOCKET) { //preverimo validnost vti�nice
		std::cout << "Error at socket(): " << WSAGetLastError() << "\n";
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	iResult = connect(connectSocket, ptr->ai_addr, (int)ptr->ai_addrlen); //kli�emo funkcijo connect, da se pove�emo na stre�nik

	if (iResult == SOCKET_ERROR) { //�e povezava ni uspela zapremo vti�nico
		closesocket(connectSocket);
		connectSocket = INVALID_SOCKET;
	}

	freeaddrinfo(result); //sprostimo spomin

	if (connectSocket == INVALID_SOCKET) { //izpis neuspesne povezave
		std::cout<< "Unable to connect to server!\n";
		WSACleanup();
		return 1;
	}

	bool running = true; //da se sercer ne izklopi
	char buffer[DEFAULT_BUFLEN]=""; //sporo�ilo
	int len = DEFAULT_BUFLEN; //velikost sporo�ila

	std::cout << "Povezava je vpostavljena !\n";

	do {

		std::cout << "Menu\n";
		std::cout << "1. nalA - Pozdravi vas ter izpise vas IP in vrata\n";
		std::cout << "2. nalB - Trenutni datum in cas\n";
		std::cout << "3. nalC - Trenutni delovni direktorij\n";
		std::cout << "4. nalD <vase sporocilo> - Izpise vase sporocilo\n";
		std::cout << "5. nalE - Sistemske informacije\n";
		std::cout << "6. nalF <forsyth�edwards notacija> - Izpis notacije\n";
		std::cout << "7. nalG <sporocilo> - Sifriranje sporocila\n";
		std::cout << "8. end - Izklopi server in povezavo\n";

		std::cout << "Vpisite ukaz : ";
		std::string msg;
		std::getline(std::cin, msg);

		iResult = send(connectSocket, msg.c_str(), strlen(msg.c_str()), 0);

		error(iResult, connectSocket, "Posijalnje ni uspelo!");

		iResult = recv(connectSocket, buffer, len, 0);

		error(iResult, connectSocket, "Prejemanje ni uspelo!");

		if (strcmp("end", buffer) == 0) {

			running = false;
		}

		else if (strncmp("nalG", msg.c_str(), 4) == 0) {

			CkCrypt2 crypt;

			crypt.put_CryptAlgorithm("3des");

			crypt.put_CipherMode("cbc");

			crypt.put_KeyLength(192);

			crypt.put_PaddingScheme(0);

			crypt.put_EncodingMode("hex");

			const char* ivHex = "0001020304050607";
			crypt.SetEncodedIV(ivHex, "hex");

			const char* keyHex = "000102030405060708090A0B0C0D0E0F0001020304050607";
			crypt.SetEncodedKey(keyHex, "hex");

			const char* decStr = crypt.decryptStringENC(buffer);
			std::cout <<"Desifrirano: " << decStr << "\r\n";
		}

		std::cout << buffer << "\n";
		memset(buffer, '\0', sizeof buffer);

	} while (running);

	iResult = shutdown(connectSocket, SD_SEND); //izklopim povezavo za po�iljanje, client lahko �e vedno prejema

	error(iResult, connectSocket, "Izklop neuspesen! ");

	closesocket(connectSocket);
	WSACleanup();

	return 0;
}


