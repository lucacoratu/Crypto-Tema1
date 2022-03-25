#pragma once

#include <iostream>
#include <string>

#define ASSERT(cond, message) do{ \
								if((cond) == true) \
									throw std::exception(message);\
							  }while(0)



#ifdef _DEBUG
	#define PRINT_DATA(data, len) for (int i = 0; i < len; i++) {\
									printf("%02x", data[i]);\
								}\
							printf("\n")
	#define DEBUG_LOG(format,...) printf(format, __VA_ARGS__)
#else
	#define PRINT_DATA 
	#define DEBUG_LOG  
#endif