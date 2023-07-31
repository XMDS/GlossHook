#include <iostream>
#include "Gloss.h"

void test()
{
	std::cout << "Hello World!" << std::endl;
}

void (*old_test)();
void my_test()
{
	std::cout << "hook 1" << std::endl;
	old_test();
}

void (*old_test2)();
void my_test2()
{
	std::cout << "hook 2" << std::endl;
	old_test2();
}

void (*old_test3)();
void my_test3()
{
	std::cout << "hook 3" << std::endl;
	old_test3();
}

int main()
{
	test();
	GlossHook((void*)test, (void*)my_test, (void**)&old_test);
	test();
	GlossHook((void*)test, (void*)my_test2, (void**)&old_test2);
	test();
	GlossHook((void*)test, (void*)my_test3, (void**)&old_test3);
	test();
	return 0;
}
