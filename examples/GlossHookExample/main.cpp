#include <iostream>
#include "Gloss.h"

__attribute__((noinline)) void test()
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
	GHook h1 = GlossHook((void*)test, (void*)my_test, (void**)&old_test);
	test();
	GHook h2 = GlossHook((void*)test, (void*)my_test2, (void**)&old_test2);
	test();
	GHook h3 = GlossHook((void*)test, (void*)my_test3, (void**)&old_test3);
	test();
	
	GlossHookDisable(h3);
	test();
	GlossHookDisable(h2);
	test();
	GlossHookDisable(h1);
	test();
	
	GlossHookEnable(h1);
	test();
	GlossHookEnable(h2);
	test();
	GlossHookEnable(h3);
	test();
	
	GlossHookDelete(h3);
	test();
	GlossHookDelete(h2);
	test();
	GlossHookDelete(h1);
	test();
	return 0;
}