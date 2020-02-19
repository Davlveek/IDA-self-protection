import os
import time

while True:
    time.sleep(10)
    os.system('taskkill /f /im ida64.exe')