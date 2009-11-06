#ifndef SANDBOX_H__
#define SANDBOX_H__

extern "C" int  SupportsSeccompSandbox(int proc_self_maps);
extern "C" void StartSeccompSandbox(int proc_self_maps);

#endif // SANDBOX_H__
