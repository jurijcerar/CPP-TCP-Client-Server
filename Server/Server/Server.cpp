#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <direct.h>
#include <CkCrypt2.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma warning( disable : 4996)

#define DEFAULT_PORT "27015"
#define DEFAULT_BUFLEN 512

struct addrinfo* result = NULL, * ptr = NULL, hints; //addrinfo struktura inicializira spremenljivke v sockadrr strukturi

void error(int iResult, SOCKET clientSocket, std::string errmsg) { //Tako preverim èe je kakšna napaka

	if (iResult == SOCKET_ERROR) { 
		std::cout << errmsg  << WSAGetLastError() << "\n";
		closesocket(clientSocket);
		WSACleanup();
		exit (1);
	}
}

void nalA(SOCKADDR_IN clientaddr, SOCKET clientSocket, int iResult) { //Naloga A

	char* ip = inet_ntoa(clientaddr.sin_addr);
	std::cout << "Pozdravljeni " << ip << ":" << clientaddr.sin_port << "\n\n";
	std::string msg = "Pozdravljen ";
	msg += ip;
	msg += ":";
	std::stringstream ss;
	ss << clientaddr.sin_port;
	msg += ss.str();
	iResult = send(clientSocket, msg.c_str(), msg.size(), 0);

	error(iResult, clientSocket, "Posiljanje ni uspelo");
}

void nalE(char* buffer, int iResult, SOCKET clientSocket) {
	DWORD dwVersion = 0;
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	DWORD dwBuild = 0;
	char name[DEFAULT_BUFLEN] = "";

	dwVersion = GetVersion();
	dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	if (dwVersion < 0x80000000) {
		dwBuild = (DWORD)(HIWORD(dwVersion));
	}

	std::ostringstream msg;

	msg << dwMajorVersion << "." << dwMinorVersion << " " << dwBuild;

	gethostname(name, sizeof name);

	std::cout << "Ime racunalnika: " << name << " Verzija Windows 10: " << msg.str()<<"\n";

	std::string temp = "Ime racunalnika: ";
	temp += name;
	temp += " Verzija Windows 10: ";
	temp += msg.str();
	temp += "\n";

	iResult = send(clientSocket, temp.c_str(), temp.size(), 0);
	error(iResult, clientSocket, "Posiljanje ni uspelo");
	
}

void nalF(char* buffer, int iResult, SOCKET clientSocket) {

	std::string line;
	std::string msg = buffer;
	std::string chess = "";
	msg = msg.substr(5);
	std::cout << "\n";

	for (int k = 0; k < 8; k++) {

		line = msg.substr(0, (msg.find('/')));
		/// <summary>
		/// Izpis šahovnice
		/// </summary>
		for (int i = 0; i < line.size(); i++) {

			if (line[i] >= 49 && line[i] <= 57) {

				for (int j = 0; j < (int)line[i]; j++) {

					chess += " ";
				}
			}

			else {
				if (i < 8) {
					chess += line[i];
				}
			}
		}

		chess += "\n";
		msg = msg.substr(msg.find('/') + 1);
	}
	/// <summary>
	/// Izpis ostalih inormacij
	/// </summary>
	for (int i = 0; i < 5; i++) {

		msg = msg.substr(msg.find(' ') + 1);
		line = msg.substr(0, msg.find(' '));

		if (line == "w") {
			chess += "Na vrsti je beli\n";
		}

		else if (line == "b") {
			chess += "Na vrsti je crni\n";
		}

		else if (i == 1) {

			for (int j = 0; j < line.size(); j++) {

				if (line[j] == 'Q') {
					chess += "Beli lahko izvede rokada na kraljicini strani\n";
				}

				else if (line[j] == 'K') {
					chess += "Beli lahko izvede rokada na kraljevi strani\n";
				}

				else if (line[j] == 'q') {
					chess += "Crni lahko izvede rokada na kraljicini strani\n";
				}

				else if (line[j] == 'k') {
					chess += "Crni lahko izvede rokada na kraljicini strani\n";
				}

				else if (line[j] == '-') {
					chess += "Rokada ni mozna nikjer\n";
				}
			}
		}

		else if (i == 2) {

			if (line == "-") {
				chess += "En passant ni mozen \n";
			}
			else {
				chess += "En passant je mozen na ";
				chess += line;
				chess += "\n";
			}
		}

		else if (i == 3) {

			chess += "Stevilo polpotez: ";
			chess += line;
			chess += "\n";
		}

		else if (i == 4) {
			chess += "Stevilka trenutne poteze: ";
			chess += line;
			chess += "\n";
		}
	}

	std::cout << chess<<"\n";
	std::cout << chess.c_str()<<"\n";
	iResult = send(clientSocket, chess.c_str(), chess.size(), 0);
	error(iResult, clientSocket, "Posiljanje ni uspelo");
}

		


int main() {

	WSADATA wsaData;
	int iResult;

	// Inicializacija Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		std::cout << "WSAStartup failed: " << iResult << "\n";
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints)); //ker niso init se uporabi ta funkcija
	hints.ai_family = AF_INET; //specificira IPv4 naslov
	hints.ai_socktype = SOCK_STREAM; //specificira stream vtiènico
	hints.ai_protocol = IPPROTO_TCP; //specificira TCP protokol
	hints.ai_flags = AI_PASSIVE; //specificira da nameravamo uporabiti vrnjeno strukturo naslova vtiènice pri klicu funkcije bind()

	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result); //init lokalnega naslova in porta za uporabo od sererja
	if (iResult != 0) {
		std::cout << "getaddrinfo failed: " << iResult << "\n";
		WSACleanup();
		return 1;
	}

	SOCKET listenSocket = INVALID_SOCKET; //to vtiènico uporabljamo za poslušanje odjemalca, INVALID_SOCKET je namesto -1, saj je SOCKET unsigned

	listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);	//uporabimo prvi IP naslov, ki ga vrne getaddrinfo, ki ustreza

	if (listenSocket == INVALID_SOCKET) { //preverimo èe je vtiènica res validna
		std::cout << "Error at socket() " << WSAGetLastError() << "\n";
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	iResult = bind(listenSocket, result->ai_addr, (int)result->ai_addrlen); //klic funckije bind v katero podamo vtiènico in sockaddr strukturo

	if (iResult == SOCKET_ERROR) { //preverimo èe so kakšne napake
		std::cout << "Bind failed with error: " << WSAGetLastError() << "\n";
		freeaddrinfo(result);
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result); //spostimo spomin, ki ga zavzamejo informacije o naslovu shranjene v getaddrinfo

	if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) { //klièemo funckijo listen in preverjamo za napake SOMAXCONN je vrednost, ki omogoèa veliko število prošenj za povezav v backlogu
		std::cout << "Listen failed with error: " << WSAGetLastError() << "\n";
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}

	SOCKET clientSocket = INVALID_SOCKET; //nova vtiènica za odjemalca
	SOCKADDR_IN clientaddr;
	int addrlen = sizeof(clientaddr);
	clientSocket = accept(listenSocket, (SOCKADDR*) &clientaddr, &addrlen); //sprejmemo odjemalca

	if (clientSocket == INVALID_SOCKET) { //preverimo za napake
		std::cout << "Accept failed with error: " << WSAGetLastError() << "\n";
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}
	else {
		std::cout << "Povezava je uspesna!\n";
	}

	bool running = true;
	char buffer[DEFAULT_BUFLEN]=""; //sporoèilo
	int len = DEFAULT_BUFLEN; //velikost sporoèila

	do { //prejema dokler se povezava ne izklopi

		iResult = recv(clientSocket, buffer, len, 0);

		error(iResult, clientSocket, "Prejem ni uspel");

		std::cout << "Dobil sem sporocilo: " << buffer << "\n";

		std::cout << "Odgovoril sem: ";

		if (strcmp("end", buffer) == 0) {

			iResult = send(clientSocket, buffer, len, 0);
			error(iResult, clientSocket, "Posiljanje ni uspelo!");
			running = false;
			memset(buffer, '\0', sizeof buffer);
		}

		else if (strcmp("nalA", buffer) == 0) {

			nalA(clientaddr, clientSocket, iResult);
			memset(buffer, '\0', sizeof buffer);
		}

		else if (strcmp("nalB", buffer) == 0) {

			auto now = std::chrono::system_clock::now();
			std::time_t time = std::chrono::system_clock::to_time_t(now);
			std::cout << std::ctime(&time);
			iResult = send(clientSocket, std::ctime(&time), strlen(std::ctime(&time)), 0);
			error(iResult, clientSocket, "Posiljanje ni uspelo!");
			memset(buffer, '\0', sizeof buffer);
		}

		else if (strcmp("nalC", buffer) == 0) {

			_getcwd(buffer, FILENAME_MAX);
			std::cout << buffer << "\n";
			iResult = send(clientSocket, buffer, len, 0);
			error(iResult, clientSocket, "Posiljanje ni uspelo!");
			memset(buffer, '\0', sizeof buffer);
		}

		else if (strncmp("nalD", buffer, 4) == 0) {

			std::string msg = buffer;
			msg = msg.substr(5);
			std::cout << msg;
			iResult = send(clientSocket, msg.c_str(), msg.size(), 0);
			memset(buffer, '\0', sizeof buffer);
			error(iResult, clientSocket, "Posiljanje ni uspelo!");
		}

		else if (strcmp("nalE", buffer) == 0) {

			nalE(buffer, iResult, clientSocket);
			memset(buffer, '\0', sizeof buffer);
		}

		else if (strncmp("nalF", buffer, 4) == 0) {

			nalF(buffer, iResult, clientSocket);
			memset(buffer, '\0', sizeof buffer);
		}

		else if (strncmp("nalG", buffer, 4) == 0) {

			CkCrypt2 crypt;

			std::string msg = buffer;
			msg = msg.substr(5);

			crypt.put_CryptAlgorithm("3des"); //izbira šifrirnika

			crypt.put_CipherMode("cbc"); //naèin šifriranja

			crypt.put_KeyLength(192); //mora biti 192

			crypt.put_PaddingScheme(0); //mora biti število deljivo z 8

			crypt.put_EncodingMode("hex"); //oblika sporocila

			const char* ivHex = "0001020304050607"; //potrebno nastaviti èe uporabljamo cbc
			crypt.SetEncodedIV(ivHex, "hex");

			const char* keyHex = "000102030405060708090A0B0C0D0E0F0001020304050607"; //kljuè
			crypt.SetEncodedKey(keyHex, "hex");

			const char* encStr = crypt.encryptStringENC(msg.c_str());  //enkripcija
			std::cout << encStr << "\r\n";

			iResult = send(clientSocket, encStr, strlen(encStr), 0);
			memset(buffer, '\0', sizeof buffer);
			error(iResult, clientSocket, "Posiljanje ni uspelo!");

		}

	} while (running);

	iResult = shutdown(clientSocket, SD_SEND);

	error(iResult, clientSocket, "Izklop neuspesen!");

	closesocket(clientSocket);
	WSACleanup();

	return 0;
}
