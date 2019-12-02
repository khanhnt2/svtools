# svattt2019

**proxy/proxy.py**: proxy server dùng để monitor, drop, modify traffic. Tool được viết dựa vào https://github.com/l0stb1t/hylian_shield

**server<spam></span>.py, client<spam></span>.py, bot<spam></span>.py**: backdoor tự động cat flag lên server và auto submit

**patch_seccomp.py**: patch binary tại entrypoint, chạy seccomp để filter syscall

**patch<spam></span>.py**: patch binary tại địa chỉ bất kì, tùy chọn shellcode. Tuy nhiên chỉ patch 1 địa chỉ cùng lúc